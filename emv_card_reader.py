#!/usr/bin/env python3
"""
EMV Smart Card Reader
Reads EMV contact cards and saves data to structured files
Author: Sive Sandla, Grok Assistant
"""

import os
import json
import datetime
from pathlib import Path
from smartcard.System import readers
from smartcard.util import toHexString, toBytes

class EMVCardReader:
    def __init__(self, output_dir="emv_sessions"):
        """Initialize the card reader with output directory"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.session_start = datetime.datetime.now()
        self.card_data = {}
        self.connection = None
        self.apdu_log = []  # Store APDU exchanges
        
    def log_apdu(self, apdu, response, sw1, sw2, direction=">"):
        """Log APDU exchanges for debugging"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if direction == ">":
            log_line = f"{timestamp} {direction} {toHexString(apdu)}"
        else:
            if response and len(response) > 0:
                log_line = f"{timestamp} < {toHexString(response)} SW1={hex(sw1)} SW2={hex(sw2)}"
            else:
                log_line = f"{timestamp} < [empty] SW1={hex(sw1)} SW2={hex(sw2)}"
        
        print(log_line)
        self.apdu_log.append(log_line)
        return log_line
    
    def send_apdu(self, apdu):
        """Send APDU and return response"""
        response, sw1, sw2 = self.connection.transmit(apdu)
        self.log_apdu(apdu, response, sw1, sw2, ">")
        if response and len(response) > 0:
            self.log_apdu(None, response, sw1, sw2, "<")
        else:
            self.log_apdu(None, None, sw1, sw2, "<")
        return response, sw1, sw2
    
    def get_response(self, length):
        """Send GET RESPONSE command"""
        get_resp = [0x00, 0xC0, 0x00, 0x00, length]
        return self.send_apdu(get_resp)
    
    def select_ppse(self):
        """Select PPSE (Proximity Payment System Environment)"""
        print("\n" + "="*60)
        print("STEP 1: SELECTING PPSE")
        print("="*60)
        
        ppse_aid = [ord(c) for c in '2PAY.SYS.DDF01']  # 13 bytes
        SELECT_PPSE = [0x00, 0xA4, 0x04, 0x00, len(ppse_aid)] + ppse_aid
        
        resp, sw1, sw2 = self.send_apdu(SELECT_PPSE)
        if sw1 == 0x61:
            resp, sw1, sw2 = self.get_response(sw2)
        
        if sw1 == 0x90 and sw2 == 0x00:
            print(f"✓ PPSE selected successfully ({len(resp)} bytes)")
            return resp
        else:
            print(f"✗ PPSE selection failed: {hex(sw1)}{hex(sw2)}")
            return None
    
    def select_aid(self, aid):
        """Select application by AID"""
        print(f"\n{'='*60}")
        print(f"STEP 2: SELECTING AID {toHexString(aid)}")
        print(f"{'='*60}")
        
        apdu = [0x00, 0xA4, 0x04, 0x00, len(aid)] + aid + [0x00]
        resp, sw1, sw2 = self.send_apdu(apdu)
        
        if sw1 == 0x61:
            resp, sw1, sw2 = self.get_response(sw2)
        
        if sw1 == 0x90 and sw2 == 0x00:
            print(f"✓ Application selected successfully ({len(resp)} bytes)")
            return resp
        else:
            print(f"✗ AID selection failed: {hex(sw1)}{hex(sw2)}")
            return None

    def parse_tlv_fixed(self, data, depth=0):
        """Fixed TLV parser that properly handles EMV record templates"""
        tlv = {}
        i = 0
        
        while i < len(data):
            if i + 1 >= len(data):
                break
            
            # Parse tag
            tag = data[i]
            i += 1
            
            # Handle multi-byte tags
            if (tag & 0x1F) == 0x1F:
                if i < len(data):
                    tag = (tag << 8) | data[i]
                    i += 1
            
            # Parse length
            if i >= len(data):
                break
            
            length = data[i]
            i += 1
            
            # Handle long form length
            if length & 0x80:
                num_length_bytes = length & 0x7F
                length = 0
                for _ in range(num_length_bytes):
                    if i < len(data):
                        length = (length << 8) | data[i]
                        i += 1
                    else:
                        break
            # Cap length to avoid buffer overflow
            length = min(length, len(data) - i)
            
            if i + length > len(data) or length <= 0:
                break
            
            value_start = i
            i += length
            
            # Create key for this TLV element
            key = hex(tag)
            
            # If this is a constructed object (template), parse recursively
            if tag & 0x20:  # Constructed object
                if tag in [0x70, 0x77, 0xA5, 0x6F, 0x61]:  # Common EMV templates
                    # Parse the template content
                    template_data = data[value_start:i]
                    tlv[key] = self.parse_tlv_fixed(template_data, depth + 1)
                else:
                    # For other constructed objects, store raw
                    tlv[key] = data[value_start:i]
            else:
                # Primitive object - store the value
                tlv[key] = data[value_start:i]
        
        return tlv

    def parse_tlv(self, data, depth=0, parent_key=""):
        """Enhanced TLV parser that handles nested templates"""
        tlv = {}
        i = 0
        
        while i < len(data):
            if i >= len(data):
                break
            
            # Parse tag
            tag = data[i]
            i += 1
            
            # Multi-byte tag
            if (tag & 0x1F) == 0x1F and i < len(data):
                tag = (tag << 8) | data[i]
                i += 1
            
            # Parse length
            if i >= len(data):
                break
            
            length_byte = data[i]
            i += 1
            
            # Handle long form length
            if length_byte & 0x80:
                length_nibbles = length_byte & 0x7F
                if length_nibbles == 1 and i < len(data):
                    length = data[i]
                    i += 1
                else:
                    length = min(length_nibbles, len(data) - i)
            else:
                length = length_byte
            
            if i + length > len(data):
                break
            
            value = data[i:i+length]
            full_key = f"{parent_key}.{hex(tag)}" if parent_key else hex(tag)
            
            # Handle constructed tags (templates) - recurse into them
            is_constructed = bool(tag & 0x20)
            if is_constructed and tag in [0x70, 0x77, 0xA5, 0x6F, 0x61, 0xBF0C]:
                tlv[full_key] = self.parse_tlv(value, depth + 1, full_key)
            else:
                tlv[full_key] = value
            
            i += length
        
        return tlv
    
    def get_tag_from_key(self, key):
        """Extract the actual tag number from a potentially nested key"""
        if isinstance(key, str) and '.' in key:
            # Extract the last part after the final dot
            tag_part = key.split('.')[-1]
            if tag_part.startswith('0x'):
                try:
                    return int(tag_part, 16)
                except ValueError:
                    return None
        elif isinstance(key, str) and key.startswith('0x'):
            try:
                return int(key, 16)
            except ValueError:
                return None
        elif isinstance(key, int):
            return key
        return None
    
    def extract_aids_from_ppse(self, ppse_resp):
        """Extract AIDs from PPSE response - FIXED VERSION"""
        print(f"\n{'='*60}")
        print("STEP 3: EXTRACTING APPLICATION IDS")
        print(f"{'='*60}")
        print(f"PPSE Response: {toHexString(ppse_resp)}")
        
        aids = []
        tlv = self.parse_tlv(ppse_resp)
        print(f"Top-level TLV keys: {list(tlv.keys())}")
        
        # Find AID (0x4F) in nested structures
        def find_aid_in_tlv(tlv_dict, path=""):
            found = False
            for key, value in tlv_dict.items():
                current_path = f"{path}.{key}" if path else key
                tag = self.get_tag_from_key(key)
                
                if tag == 0x4F and isinstance(value, (list, bytes)):
                    aids.append(value)
                    print(f"  ✓ Found AID at {current_path}: {toHexString(value)}")
                    found = True
                    continue  # Continue searching for more AIDs
                
                if isinstance(value, dict):
                    if find_aid_in_tlv(value, current_path):
                        found = True
            
            return found
        
        # Search for AIDs
        if find_aid_in_tlv(tlv):
            print(f"\n  Found {len(aids)} application(s) via TLV parsing")
        else:
            print("  No AIDs found via TLV parsing, trying brute force...")
            # Fallback: brute force search
            i = 0
            while i < len(ppse_resp) - 1:
                if ppse_resp[i] == 0x4F:
                    length = ppse_resp[i + 1]
                    if i + 2 + length <= len(ppse_resp):
                        aid = ppse_resp[i + 2:i + 2 + length]
                        aids.append(aid)
                        print(f"  ✓ Found AID via brute force: {toHexString(aid)}")
                        i += 2 + length
                    else:
                        i += 1
                else:
                    i += 1
        
        for i, aid in enumerate(aids, 1):
            print(f"    {i}. {toHexString(aid)}")
        
        return aids if aids else [[0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10]]  # Mastercard fallback

    def parse_fci_fixed(self, fci_data):
        """Fixed FCI parsing - direct byte pattern search"""
        print(f"\n{'='*60}")
        print("STEP 4: PARSING APPLICATION METADATA")
        print(f"{'='*60}")
        print(f"FCI Response ({len(fci_data)} bytes): {toHexString(fci_data)}")
        
        fci_info = {}
        
        # Method 1: Direct pattern search for known tags
        i = 0
        while i < len(fci_data) - 4:
            tag = fci_data[i]
            
            # Application ID (0x84)
            if tag == 0x84 and i + 3 < len(fci_data):
                aid_length = fci_data[i+1]
                if i + 2 + aid_length <= len(fci_data):
                    aid = fci_data[i+2:i+2+aid_length]
                    fci_info['application_id'] = toHexString(aid)
                    print(f"  ✓ Application ID: {toHexString(aid)}")
            
            # Application Label (0x50)
            elif tag == 0x50 and i + 3 < len(fci_data):
                label_length = fci_data[i+1]
                if i + 2 + label_length <= len(fci_data):
                    label_bytes = fci_data[i+2:i+2+label_length]
                    label = ''.join(chr(b) for b in label_bytes if 32 <= b <= 126).strip()
                    if label:
                        fci_info['application_label'] = label
                        print(f"  ✓ Application Label: '{label}'")
            
            # Preferred Name (0x9F12)
            elif tag == 0x9F and i + 1 < len(fci_data) and fci_data[i+1] == 0x12:
                name_length = fci_data[i+2]
                if i + 3 + name_length <= len(fci_data):
                    name_bytes = fci_data[i+3:i+3+name_length]
                    name = ''.join(chr(b) for b in name_bytes if 32 <= b <= 126).strip()
                    if name:
                        fci_info['preferred_name'] = name
                        print(f"  ✓ Preferred Name: '{name}'")
            
            # Language Preference (0x5F2D)
            elif tag == 0x5F and i + 1 < len(fci_data) and fci_data[i+1] == 0x2D:
                lang_length = fci_data[i+2]
                if i + 3 + lang_length <= len(fci_data) and lang_length >= 2:
                    lang_bytes = fci_data[i+3:i+3+lang_length]
                    lang_str = ''.join(chr(b) for b in lang_bytes).strip().lower()
                    if len(lang_str) >= 2:
                        fci_info['language'] = lang_str
                        print(f"  ✓ Language: {lang_str}")
            
            # Application Version (0x9F6E) - this is trickier, usually nested
            elif tag == 0x9F and i + 1 < len(fci_data) and fci_data[i+1] == 0x6E:
                version_length = fci_data[i+2]
                if i + 3 + version_length <= len(fci_data) and version_length >= 2:
                    version_bytes = fci_data[i+3:i+3+version_length]
                    if len(version_bytes) >= 2:
                        fci_info['app_version'] = f"{version_bytes[0]:02X}.{version_bytes[1]:02X}"
                        print(f"  ✓ Application Version: {fci_info['app_version']}")
            
            i += 1
        
        # Method 2: Fallback TLV parsing
        if not fci_info:
            print("  Method 1 failed, trying TLV parsing...")
            try:
                tlv = self.parse_tlv_fixed(fci_data)
                for key, value in tlv.items():
                    tag = int(key, 16)
                    
                    if tag == 0x84 and isinstance(value, (list, bytes)):
                        fci_info['application_id'] = toHexString(value)
                        print(f"  ✓ Application ID (TLV): {fci_info['application_id']}")
                    
                    elif tag == 0x50 and isinstance(value, (list, bytes)):
                        name = ''.join(chr(b) for b in value if 32 <= b <= 126).strip()
                        if name:
                            fci_info['application_label'] = name
                            print(f"  ✓ Application Label (TLV): '{name}'")
                            
                    elif tag == 0x9F12 and isinstance(value, (list, bytes)):
                        name = ''.join(chr(b) for b in value if 32 <= b <= 126).strip()
                        if name:
                            fci_info['preferred_name'] = name
                            print(f"  ✓ Preferred Name (TLV): '{name}'")
                            
                    elif tag == 0x5F2D and isinstance(value, (list, bytes)):
                        lang_str = ''.join(chr(b) for b in value).strip().lower()
                        if len(lang_str) >= 2:
                            fci_info['language'] = lang_str
                            print(f"  ✓ Language (TLV): {lang_str}")
                            
                    elif tag == 0x9F6E and isinstance(value, (list, bytes)) and len(value) >= 2:
                        fci_info['app_version'] = f"{value[0]:02X}.{value[1]:02X}"
                        print(f"  ✓ Application Version (TLV): {fci_info['app_version']}")
                        
                    # Check nested structures
                    if isinstance(value, dict):
                        for sub_key, sub_value in value.items():
                            sub_tag = int(sub_key, 16)
                            if sub_tag == 0x9F6E and isinstance(sub_value, (list, bytes)) and len(sub_value) >= 2:
                                fci_info['app_version'] = f"{sub_value[0]:02X}.{sub_value[1]:02X}"
                                print(f"  ✓ Application Version (nested): {fci_info['app_version']}")
            
            except Exception as e:
                print(f"  TLV parsing error: {e}")
        
        return fci_info

    def parse_fci(self, fci_data):
        """Parse FCI response for application metadata - FIXED VERSION"""
        print(f"\n{'='*60}")
        print("STEP 4: PARSING APPLICATION METADATA")
        print(f"{'='*60}")
        print(f"FCI Response ({len(fci_data)} bytes): {toHexString(fci_data)}")
        
        fci_info = {}
        tlv = self.parse_tlv(fci_data)
        
        # Application ID (0x84)
        for key in list(tlv.keys()):
            if self.get_tag_from_key(key) == 0x84:
                aid = tlv[key]
                fci_info['application_id'] = toHexString(aid)
                print(f"  ✓ Application ID: {toHexString(aid)}")
                break
        
        # FCI Proprietary Template (0xA5)
        for key in list(tlv.keys()):
            if self.get_tag_from_key(key) == 0xA5:
                prop_tlv = tlv[key]
                print(f"  Parsing FCI Proprietary Template: {list(prop_tlv.keys())}")
                
                # Application Label (0x50)
                for prop_key in list(prop_tlv.keys()):
                    if self.get_tag_from_key(prop_key) == 0x50:
                        label = prop_tlv[prop_key]
                        name = ''.join(chr(b) for b in label if 32 <= b <= 126).strip()
                        fci_info['application_label'] = name
                        print(f"  ✓ Application Label: '{name}'")
                        break
                
                # Preferred Name (0x9F12)
                for prop_key in list(prop_tlv.keys()):
                    if self.get_tag_from_key(prop_key) == 0x9F12:
                        pref_name = prop_tlv[prop_key]
                        name = ''.join(chr(b) for b in pref_name if 32 <= b <= 126).strip()
                        fci_info['preferred_name'] = name
                        print(f"  ✓ Preferred Name: '{name}'")
                        break
                
                # Language Preference (0x5F2D)
                for prop_key in list(prop_tlv.keys()):
                    if self.get_tag_from_key(prop_key) == 0x5F2D:
                        lang = prop_tlv[prop_key]
                        lang_str = ''.join(chr(b) for b in lang).strip().lower()
                        fci_info['language'] = lang_str
                        print(f"  ✓ Language: {lang_str}")
                        break
                
                # Application Version (0x9F6E) - nested in BF0C
                if '0xbf0c' in prop_tlv:
                    issuer_tlv = prop_tlv['0xbf0c']
                    for issuer_key in list(issuer_tlv.keys()):
                        if self.get_tag_from_key(issuer_key) == 0x9F6E:
                            version = issuer_tlv[issuer_key]
                            if len(version) >= 2:
                                fci_info['app_version'] = f"{version[0]:02X}.{version[1]:02X}"
                                print(f"  ✓ Application Version: {fci_info['app_version']}")
                            break
                break
        
        return fci_info
    
    def read_card_records(self):
        """Read all available records from the card"""
        print(f"\n{'='*60}")
        print("STEP 5: READING CARD RECORDS")
        print(f"{'='*60}")
        
        records = {}
        total_bytes = 0
        
        # SFIs that worked in your previous output
        sfis_to_try = [1, 2, 3, 4]
        
        for sfi in sfis_to_try:
            print(f"\n  Scanning SFI {sfi}...")
            records[f"sfi_{sfi}"] = {}
            p2_base = (sfi << 3) | 0x04
            
            record_count = 0
            for record_num in range(1, 10):
                # Try with Le=0 first
                apdu = [0x00, 0xB2, record_num, p2_base, 0x00]
                resp, sw1, sw2 = self.send_apdu(apdu)
                
                # Handle GET RESPONSE
                if sw1 == 0x61:
                    resp, sw1, sw2 = self.get_response(sw2)
                
                # Handle wrong length (6Cxx)
                if sw1 == 0x6C and sw2 <= 256:
                    apdu[-1] = sw2
                    resp, sw1, sw2 = self.send_apdu(apdu)
                    if sw1 == 0x61:
                        resp, sw1, sw2 = self.get_response(sw2)
                
                if sw1 == 0x90 and sw2 == 0x00 and len(resp) > 0:
                    record_name = f"record_{record_num}"
                    records[f"sfi_{sfi}"][record_name] = {
                        'data': resp,
                        'hex': toHexString(resp),
                        'length': len(resp)
                    }
                    total_bytes += len(resp)
                    record_count += 1
                    print(f"    ✓ Record {record_num}: {len(resp)} bytes")
                elif sw1 == 0x6A and sw2 in [0x82, 0x83]:
                    print(f"    ! End of records for SFI {sfi}")
                    break
                elif sw1 == 0x69 and sw2 == 0x85:
                    print(f"    ! Access denied for SFI {sfi}, Record {record_num}")
                    break
                else:
                    print(f"    - Record {record_num}: {hex(sw1)}{hex(sw2)}")
            
            print(f"    Found {record_count} records in SFI {sfi}")
        
        print(f"\n  Total records read: {sum(len(sfi_records) for sfi_records in records.values())}")
        print(f"  Total bytes: {total_bytes}")
        
        return records

    def extract_cardholder_data_fixed(self, records):
        """Fixed cardholder data extraction - directly searches raw data"""
        print(f"\n{'='*60}")
        print("STEP 6: EXTRACTING CARDHOLDER DATA")
        print(f"{'='*60}")
        
        card_data = {}
        
        # Method 1: Direct TLV parsing of all data
        all_data = []
        for sfi_data in records.values():
            for record_data in sfi_data.values():
                all_data.extend(record_data['data'])
        
        print(f"  Method 1: Analyzing {len(all_data)} total bytes via TLV...")
        tlv = self.parse_tlv_fixed(all_data)
        
        def extract_from_tlv(tlv_dict):
            for key, value in tlv_dict.items():
                tag = int(key, 16) if key.startswith('0x') else int(key)
                
                if isinstance(value, dict):
                    extract_from_tlv(value)
                else:
                    # Primary Account Number (0x5A)
                    if tag == 0x5A:
                        pan = value
                        if len(pan) >= 8:  # Minimum 16-digit PAN
                            pan_str = ''.join(f"{b:02X}" for b in pan)
                            if len(pan_str) >= 16 and pan_str.isdigit():
                                masked_pan = f"{pan_str[:6]}******{pan_str[-4:]}"
                                card_data['pan'] = pan_str
                                card_data['pan_masked'] = masked_pan
                                print(f"  ✓ PAN: {masked_pan} (full: {pan_str})")
                    
                    # Application Expiration Date (0x5F24)
                    elif tag == 0x5F24:
                        expiry = value
                        if len(expiry) >= 3:
                            year = expiry[0]
                            month = expiry[1]
                            day = expiry[2] if len(expiry) > 2 else 31
                            expiry_str = f"20{year:02X}-{month:02X}-{day:02X}"
                            card_data['expiry_date'] = expiry_str
                            print(f"  ✓ Expiry Date: {expiry_str}")
                    
                    # Cardholder Name (0x5F20)
                    elif tag == 0x5F20:
                        name_bytes = value
                        name = ''.join(chr(b) for b in name_bytes if 32 <= b <= 126).strip()
                        if name and len(name) > 1:
                            card_data['cardholder_name'] = name
                            print(f"  ✓ Cardholder Name: '{name}'")
                    
                    # Track 2 Equivalent Data (0x57)
                    elif tag == 0x57:
                        track2 = value
                        track2_str = ''.join(f"{b:02X}" for b in track2)
                        print(f"  Track 2 Data: {track2_str[:50]}...")
                        if 'D' in track2_str:
                            parts = track2_str.split('D')
                            if len(parts) > 0 and len(parts[0]) >= 16:
                                pan_part = parts[0]
                                if pan_part.isdigit():
                                    masked = f"{pan_part[:6]}******{pan_part[-4:]}"
                                    card_data['track2_pan'] = pan_part
                                    card_data['track2_pan_masked'] = masked
                                    print(f"  ✓ Track 2 PAN: {masked}")
                            
                            if len(parts) > 1 and len(parts[1]) >= 4:
                                expiry_part = parts[1][:4]
                                if expiry_part.isdigit():
                                    year = int(expiry_part[:2])
                                    month = int(expiry_part[2:4])
                                    expiry_str = f"20{year:02d}-{month:02d}"
                                    card_data['track2_expiry'] = expiry_str
                                    print(f"  ✓ Track 2 Expiry: {expiry_str}")
                    
                    # Service Code (0x5F30)
                    elif tag == 0x5F30:
                        service = ''.join(f"{b:02X}" for b in value)
                        card_data['service_code'] = service
                        print(f"  ✓ Service Code: {service}")
        
        extract_from_tlv(tlv)
        
        # Method 2: Direct byte pattern search (fallback)
        if not card_data:
            print(f"  Method 1 failed, trying direct pattern search...")
            
            # Search for cardholder name pattern: 5F 20 XX [ASCII text]
            i = 0
            while i < len(all_data) - 4:
                if (all_data[i] == 0x5F and all_data[i+1] == 0x20 and 
                    0x01 <= all_data[i+2] <= 0x1F):  # Valid length for name
                    name_start = i + 3
                    name_length = all_data[i+2]
                    if name_start + name_length <= len(all_data):
                        name_bytes = all_data[name_start:name_start + name_length]
                        name = ''.join(chr(b) for b in name_bytes if 32 <= b <= 126).strip()
                        if len(name) > 1:
                            card_data['cardholder_name'] = name
                            print(f"  ✓ Cardholder Name (pattern): '{name}'")
                            break
                i += 1
            
            # Search for PAN pattern: 5A XX [BCD digits]
            i = 0
            while i < len(all_data) - 4:
                if all_data[i] == 0x5A and 0x04 <= all_data[i+1] <= 0x0C:  # 8-24 BCD digits
                    pan_start = i + 2
                    pan_length = all_data[i+1]
                    if pan_start + pan_length <= len(all_data):
                        pan_bytes = all_data[pan_start:pan_start + pan_length]
                        # Convert BCD to decimal string
                        pan_str = ''
                        for b in pan_bytes:
                            pan_str += f"{(b >> 4) & 0xF}{b & 0xF}"
                        
                        if len(pan_str) >= 16 and pan_str.isdigit():
                            masked_pan = f"{pan_str[:6]}******{pan_str[-4:]}"
                            card_data['pan'] = pan_str
                            card_data['pan_masked'] = masked_pan
                            print(f"  ✓ PAN (pattern): {masked_pan}")
                            break
                i += 1
            
            # Search for expiry pattern: 5F 24 03 YY MM DD
            i = 0
            while i < len(all_data) - 5:
                if (all_data[i] == 0x5F and all_data[i+1] == 0x24 and 
                    all_data[i+2] == 0x03):  # 3-byte expiry
                    expiry_start = i + 3
                    if expiry_start + 3 <= len(all_data):
                        year = all_data[expiry_start]
                        month = all_data[expiry_start + 1]
                        day = all_data[expiry_start + 2]
                        expiry_str = f"20{year:02X}-{month:02X}-{day:02X}"
                        card_data['expiry_date'] = expiry_str
                        print(f"  ✓ Expiry Date (pattern): {expiry_str}")
                        break
                i += 1
        
        # Method 3: Search individual records (most reliable)
        if not card_data:
            print(f"  Method 2 failed, searching individual records...")
            
            for sfi_name, sfi_records in records.items():
                for record_name, record_data in sfi_records.items():
                    record_data = record_data['data']
                    print(f"  Searching {sfi_name} {record_name} ({len(record_data)} bytes)...")
                    
                    # Check for cardholder name (0x5F20)
                    i = 0
                    while i < len(record_data) - 4:
                        if (record_data[i] == 0x5F and record_data[i+1] == 0x20 and 
                            0x01 <= record_data[i+2] <= 0x1F):
                            name_start = i + 3
                            name_length = record_data[i+2]
                            if name_start + name_length <= len(record_data):
                                name_bytes = record_data[name_start:name_start + name_length]
                                name = ''.join(chr(b) for b in name_bytes if 32 <= b <= 126).strip()
                                if len(name) > 1 and 'cardholder_name' not in card_data:
                                    card_data['cardholder_name'] = name
                                    print(f"  ✓ Cardholder Name: '{name}' in {sfi_name} {record_name}")
                        
                        # Check for PAN (0x5A)
                        if (record_data[i] == 0x5A and 0x04 <= record_data[i+1] <= 0x0C):
                            pan_start = i + 2
                            pan_length = record_data[i+1]
                            if pan_start + pan_length <= len(record_data):
                                pan_bytes = record_data[pan_start:pan_start + pan_length]
                                pan_str = ''
                                for b in pan_bytes:
                                    pan_str += f"{(b >> 4) & 0xF}{b & 0xF}"
                                
                                if len(pan_str) >= 16 and pan_str.isdigit() and 'pan' not in card_data:
                                    masked_pan = f"{pan_str[:6]}******{pan_str[-4:]}"
                                    card_data['pan'] = pan_str
                                    card_data['pan_masked'] = masked_pan
                                    print(f"  ✓ PAN: {masked_pan} in {sfi_name} {record_name}")
                        
                        # Check for expiry (0x5F24)
                        if (record_data[i] == 0x5F and record_data[i+1] == 0x24 and 
                            record_data[i+2] == 0x03):
                            expiry_start = i + 3
                            if expiry_start + 3 <= len(record_data):
                                year = record_data[expiry_start]
                                month = record_data[expiry_start + 1]
                                day = record_data[expiry_start + 2]
                                expiry_str = f"20{year:02X}-{month:02X}-{day:02X}"
                                if 'expiry_date' not in card_data:
                                    card_data['expiry_date'] = expiry_str
                                    print(f"  ✓ Expiry Date: {expiry_str} in {sfi_name} {record_name}")
                        
                        i += 1
        
        print(f"\n  Extraction complete: {len(card_data)} data elements found")
        return card_data

    def extract_cardholder_data(self, records):
        """Extract meaningful data from records - FIXED VERSION"""
        print(f"\n{'='*60}")
        print("STEP 6: EXTRACTING CARDHOLDER DATA")
        print(f"{'='*60}")
        
        all_data = []
        for sfi_data in records.values():
            for record_data in sfi_data.values():
                all_data.extend(record_data['data'])
        
        print(f"  Analyzing {len(all_data)} total bytes...")
        card_data = {}
        tlv = self.parse_tlv(all_data)
        
        def search_tlv_recursive(tlv_dict, path=""):
            for key, value in tlv_dict.items():
                current_path = f"{path}.{key}" if path else key
                tag = self.get_tag_from_key(key)
                
                if isinstance(value, dict):
                    search_tlv_recursive(value, current_path)
                else:
                    if tag is None:
                        continue
                    
                    # Primary Account Number (0x5A)
                    if tag == 0x5A:
                        pan = value
                        pan_str = ''.join(f"{b:02X}" for b in pan).strip()
                        if len(pan_str) >= 13:  # Minimum valid PAN length
                            masked_pan = f"{pan_str[:6]}******{pan_str[-4:]}"
                            card_data['pan'] = pan_str
                            card_data['pan_masked'] = masked_pan
                            print(f"  ✓ PAN: {masked_pan}")
                    
                    # Application Expiration Date (0x5F24)
                    elif tag == 0x5F24:
                        expiry = value
                        if len(expiry) >= 3:
                            year = expiry[0]
                            month = expiry[1]
                            day = expiry[2] if len(expiry) > 2 else 31
                            expiry_str = f"20{year:02X}-{month:02X}-{day:02X}"
                            card_data['expiry_date'] = expiry_str
                            print(f"  ✓ Expiry Date: {expiry_str}")
                    
                    # Cardholder Name (0x5F20)
                    elif tag == 0x5F20:
                        name_bytes = value
                        name = ''.join(chr(b) for b in name_bytes if 32 <= b <= 126).strip()
                        if name and len(name) > 1:
                            card_data['cardholder_name'] = name
                            print(f"  ✓ Cardholder Name: '{name}'")
                    
                    # Track 2 Equivalent Data (0x57)
                    elif tag == 0x57:
                        track2 = value
                        track2_str = ''.join(f"{b:02X}" for b in track2)
                        print(f"  Track 2 Data: {track2_str[:50]}...")
                        if 'D' in track2_str:
                            parts = track2_str.split('D')
                            if len(parts) > 0 and len(parts[0]) >= 13:
                                pan_part = parts[0]
                                masked = f"{pan_part[:6]}******{pan_part[-4:]}"
                                card_data['track2_pan'] = pan_part
                                card_data['track2_pan_masked'] = masked
                                print(f"  ✓ Track 2 PAN: {masked}")
                            
                            if len(parts) > 1 and len(parts[1]) >= 4:
                                expiry_part = parts[1][:4]
                                if expiry_part.isdigit():
                                    year = int(expiry_part[:2])
                                    month = int(expiry_part[2:4])
                                    expiry_str = f"20{year:02d}-{month:02d}"
                                    card_data['track2_expiry'] = expiry_str
                                    print(f"  ✓ Track 2 Expiry: {expiry_str}")
                    
                    # Service Code (0x5F30)
                    elif tag == 0x5F30:
                        service = ''.join(f"{b:02X}" for b in value)
                        card_data['service_code'] = service
                        print(f"  ✓ Service Code: {service}")
        
        search_tlv_recursive(tlv)
        return card_data
    
    def save_session_files(self, fci_info, cardholder_data, records, aid):
        """Save all data to structured files"""
        print(f"\n{'='*60}")
        print("STEP 7: SAVING SESSION FILES")
        print(f"{'='*60}")
        
        # Generate unique session ID
        session_id = self.session_start.strftime("%Y%m%d_%H%M%S")
        card_id = f"{toHexString(aid[:4]).replace(' ', '').upper()}_{session_id}"
        session_dir = self.output_dir / card_id
        session_dir.mkdir(exist_ok=True)
        
        print(f"   Saving to: {session_dir}")
        
        # 1. Main JSON summary
        total_bytes = sum(len(r['data']) for s in records.values() for r in s.values())
        summary = {
            'session': {
                'timestamp': self.session_start.isoformat(),
                'card_reader': str(readers()[0]) if readers() else 'Unknown',
                'session_id': session_id
            },
            'application': {
                'aid': toHexString(aid),
                **{k: v for k, v in fci_info.items() if k != 'application_id'}
            },
            'cardholder': {
                'name': cardholder_data.get('cardholder_name', 'Not found'),
                'pan': cardholder_data.get('pan', 'Not found'),
                'pan_masked': cardholder_data.get('pan_masked', 'Not found'),
                'expiry_date': cardholder_data.get('expiry_date', 'Not found')
            },
            'technical': {
                'total_bytes_read': total_bytes,
                'records_count': len([r for s in records.values() for r in s.values()])
            }
        }
        
        # Save summary
        summary_path = session_dir / "card_summary.json"
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        print(f"  ✓ Summary: {summary_path}")
        
        # 2. Raw APDU log
        apdu_log_path = session_dir / "apdu_log.txt"
        with open(apdu_log_path, 'w', encoding='utf-8') as f:
            f.write(f"EMV Card Session Log\n")
            f.write(f"Generated: {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Card ID: {card_id}\n")
            f.write(f"AID: {toHexString(aid)}\n")
            f.write(f"APDU Exchanges: {len(self.apdu_log)}\n")
            f.write("="*60 + "\n\n")
            
            # Write all logged APDUs
            for log_line in self.apdu_log:
                f.write(f"{log_line}\n")
            
            f.write(f"\n\n{'='*60}\n")
            f.write("SESSION SUMMARY\n")
            f.write(f"{'='*60}\n")
            f.write(f"Application: {fci_info.get('application_label', 'Unknown')}\n")
            f.write(f"Cardholder: {cardholder_data.get('cardholder_name', 'Unknown')}\n")
            f.write(f"PAN: {cardholder_data.get('pan_masked', 'Not found')}\n")
            f.write(f"Expires: {cardholder_data.get('expiry_date', 'Not found')}\n")
            f.write(f"Total Data: {total_bytes} bytes\n")
        
        print(f"  ✓ APDU Log: {apdu_log_path}")
        
        # 3. Raw records dump
        records_path = session_dir / "raw_records.txt"
        with open(records_path, 'w', encoding='utf-8') as f:
            f.write(f"Raw EMV Records Dump\n")
            f.write(f"Session: {session_id}\n")
            f.write(f"Total Bytes: {total_bytes}\n")
            f.write(f"{'='*60}\n")
            
            for sfi_name, sfi_records in records.items():
                f.write(f"\n[{sfi_name.upper()}]\n")
                f.write(f"{'-'*40}\n")
                for record_name, record_data in sfi_records.items():
                    f.write(f"{record_name.upper()}: {record_data['hex']}\n")
                    f.write(f"  Length: {record_data['length']} bytes\n")
                    f.write(f"  Raw:    {record_data['data']}\n\n")
        
        print(f"  ✓ Raw Records: {records_path}")
        
        # 4. Detailed TLV analysis
        all_data = []
        for sfi_data in records.values():
            for record_data in sfi_data.values():
                all_data.extend(record_data['data'])
        
        tlv_path = session_dir / "tlv_analysis.json"
        tlv_analysis = {
            'all_data_length': len(all_data),
            'tlv_structure': self.parse_tlv(all_data),
            'extracted_tags': {}
        }
        
        # Add some basic tag statistics
        def count_tags(tlv_dict):
            for key, value in tlv_dict.items():
                tag = self.get_tag_from_key(key)
                if tag is not None:
                    tlv_analysis['extracted_tags'][hex(tag)] = tlv_analysis['extracted_tags'].get(hex(tag), 0) + 1
                if isinstance(value, dict):
                    count_tags(value)
        
        count_tags(tlv_analysis['tlv_structure'])
        
        with open(tlv_path, 'w', encoding='utf-8') as f:
            json.dump(tlv_analysis, f, indent=2, default=str, ensure_ascii=False)
        print(f"  ✓ TLV Analysis: {tlv_path}")
        
        # 5. Human-readable card info
        card_info_path = session_dir / "card_info.txt"
        with open(card_info_path, 'w', encoding='utf-8') as f:
            f.write("="*50 + "\n")
            f.write("         EMV CARD INFORMATION\n")
            f.write("="*50 + "\n\n")
            f.write(f" Session ID: {session_id}\n")
            f.write(f" Read Time: {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f" Reader: {str(readers()[0]) if readers() else 'Unknown'}\n\n")
            f.write("-"*50 + "\n\n")
            
            if 'application_label' in fci_info:
                f.write(f" Card Type: {fci_info['application_label']}\n")
            if 'preferred_name' in fci_info:
                f.write(f" Issuer:    {fci_info['preferred_name']}\n")
            if 'cardholder_name' in cardholder_data:
                f.write(f" Holder:    {cardholder_data['cardholder_name']}\n")
            if 'pan_masked' in cardholder_data:
                f.write(f" Number:    {cardholder_data['pan_masked']}\n")
            if 'expiry_date' in cardholder_data:
                f.write(f" Expires:   {cardholder_data['expiry_date']}\n")
            if 'language' in fci_info:
                f.write(f" Language:  {fci_info['language']}\n")
            if 'service_code' in cardholder_data:
                f.write(f"⚙️  Service:   {cardholder_data['service_code']}\n")
            
            f.write("\n" + "-"*50 + "\n")
            f.write(f" Technical: {total_bytes} bytes read, {len([r for s in records.values() for r in s.values()])} records\n")
        
        print(f"  ✓ Card Info: {card_info_path}")
        
        # 6. README
        readme_path = session_dir / "README.md"
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(f"# EMV Card Session: {session_id}\n\n")
            f.write(f"**Read on:** {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Card Type:** {fci_info.get('application_label', 'Unknown EMV Card')}\n")
            f.write(f"**PAN:** {cardholder_data.get('pan_masked', 'Not available')}\n")
            f.write(f"**Expires:** {cardholder_data.get('expiry_date', 'Not available')}\n\n")
            
            f.write("## Files Included\n\n")
            f.write("* `card_summary.json` - Complete structured data\n")
            f.write("* `apdu_log.txt` - Full APDU exchange log\n")
            f.write("* `raw_records.txt` - All raw EMV records with hex dump\n")
            f.write("* `tlv_analysis.json` - Complete TLV structure and tag analysis\n")
            f.write("* `card_info.txt` - Human-readable card summary\n")
            f.write("* `README.md` - This documentation\n\n")
            
            f.write("## Card Details\n\n")
            if 'application_label' in fci_info:
                f.write(f"**Application:** {fci_info['application_label']}\n")
            if 'preferred_name' in fci_info:
                f.write(f"**Issuer:** {fci_info['preferred_name']}\n")
            if 'cardholder_name' in cardholder_data:
                f.write(f"**Cardholder:** {cardholder_data['cardholder_name']}\n")
            if 'pan' in cardholder_data:
                f.write(f"**PAN:** {cardholder_data['pan']}\n")
            if 'expiry_date' in cardholder_data:
                f.write(f"**Expiry Date:** {cardholder_data['expiry_date']}\n")
            if 'app_version' in fci_info:
                f.write(f"**App Version:** {fci_info['app_version']}\n")
            
            f.write(f"\n**Technical:** {total_bytes} bytes read across {len([r for s in records.values() for r in s.values()])} records\n")
        
        print(f"  ✓ README: {readme_path}")
        
        # Create a simple HTML report
        html_path = session_dir / "report.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>EMV Card Report - {session_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .card {{ border: 2px solid #007bff; border-radius: 10px; padding: 20px; margin: 20px 0; }}
        .header {{ background: #007bff; color: white; padding: 15px; border-radius: 5px; }}
        .info {{ display: grid; grid-template-columns: 150px 1fr; gap: 10px; margin: 10px 0; }}
        .data {{ background: #f8f9fa; padding: 10px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>EMV Card Analysis Report</h1>
        <p>Session: {session_id} | Read: {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="card">
        <h2>Card Information</h2>
        <div class="info">
            <div><strong>Card Type:</strong></div>
            <div class="data">{fci_info.get('application_label', 'Unknown')}</div>
            
            <div><strong>Issuer:</strong></div>
            <div class="data">{fci_info.get('preferred_name', 'N/A')}</div>
            
            <div><strong>Cardholder:</strong></div>
            <div class="data">{cardholder_data.get('cardholder_name', 'N/A')}</div>
            
            <div><strong>Card Number:</strong></div>
            <div class="data">{cardholder_data.get('pan_masked', 'N/A')}</div>
            
            <div><strong>Expires:</strong></div>
            <div class="data">{cardholder_data.get('expiry_date', 'N/A')}</div>
            
            <div><strong>Language:</strong></div>
            <div class="data">{fci_info.get('language', 'N/A')}</div>
            
            <div><strong>App Version:</strong></div>
            <div class="data">{fci_info.get('app_version', 'N/A')}</div>
        </div>
    </div>
    
    <div class="card">
        <h2>Technical Summary</h2>
        <div class="info">
            <div><strong>AID:</strong></div>
            <div class="data">{toHexString(aid)}</div>
            
            <div><strong>Total Data:</strong></div>
            <div class="data">{total_bytes} bytes</div>
            
            <div><strong>Records:</strong></div>
            <div class="data">{len([r for s in records.values() for r in s.values()])} records</div>
        </div>
    </div>
</body>
</html>""")
        
        print(f"  ✓ HTML Report: {html_path}")
        
        print(f"\n   Session saved successfully: {session_dir}")
        return str(session_dir)
    
    def read_card(self):
        """Main function to read the entire card"""
        print(" EMV Smart Card Reader")
        print(f" Session started: {self.session_start}")
        print(f" Output directory: {self.output_dir}")
        print("-" * 60)
        
        try:
            # Initialize connection
            if not readers():
                print("✗ No smart card readers found!")
                return None
            
            reader = readers()[0]
            print(f" Using reader: {reader}")
            
            self.connection = reader.createConnection()
            self.connection.connect()
            print(" Card connected successfully")
            
            # Step 1: Select PPSE
            ppse_resp = self.select_ppse()
            if not ppse_resp:
                return None
            
            # Step 2: Extract AIDs
            aids = self.extract_aids_from_ppse(ppse_resp)
            if not aids:
                print("✗ No applications found on card!")
                return None
            
            # Step 3: Process first AID
            aid = aids[0]  # Use first application
            select_resp = self.select_aid(aid)
            if not select_resp:
                return None
            
            # Step 4: Parse FCI
            fci_info = self.parse_fci_fixed(select_resp)
            
            # Step 5: Read records
            records = self.read_card_records()
            
            # Step 6: Extract cardholder data
            cardholder_data = self.extract_cardholder_data_fixed(records)
            
            # Step 7: Save everything
            session_path = self.save_session_files(fci_info, cardholder_data, records, aid)
            
            print(f"\n CARD READING COMPLETE!")
            print(f" Data saved to: {session_path}")
            
            # Final summary
            print(f"\n{'='*60}")
            print("FINAL SUMMARY")
            print(f"{'='*60}")
            print(f" Card: {fci_info.get('application_label', 'Unknown EMV Card')}")
            print(f" Holder: {cardholder_data.get('cardholder_name', 'Not found')}")
            print(f" Number: {cardholder_data.get('pan_masked', 'Not found')}")
            print(f" Expires: {cardholder_data.get('expiry_date', 'Not found')}")
            print(f" Language: {fci_info.get('language', 'Not specified')}")
            print(f" Data: {sum(len(r['data']) for s in records.values() for r in s.values())} bytes")
            
            return {
                'session_path': session_path,
                'cardholder_data': cardholder_data,
                'fci_info': fci_info,
                'records_count': len([r for s in records.values() for r in s.values()])
            }
            
        except Exception as e:
            print(f" Error during card reading: {e}")
            import traceback
            traceback.print_exc()
            return None
        finally:
            if self.connection:
                try:
                    self.connection.disconnect()
                    print(" Card disconnected")
                except Exception as e:
                    print(f"  Disconnect warning: {e}")

def main():
    """Main entry point"""
    print(" Starting EMV Card Reader")
    print("=" * 60)
    
    # Create reader instance
    reader = EMVCardReader("emv_sessions")
    
    # Read card
    result = reader.read_card()
    
    if result:
        print(f"\n Success! Session saved to: {result['session_path']}")
        print(f" Found {result['records_count']} records")
        print(f"\n Check the '{reader.output_dir}' directory for all files!")
    else:
        print("\n Card reading failed or no data found")
        print("\n Tips:")
        print("   - Ensure your EMV card is properly inserted")
        print("   - Check that your reader supports contact cards")
        print("   - Try a different EMV card if available")
    
    print("\n Program complete.")

if __name__ == "__main__":
    main()