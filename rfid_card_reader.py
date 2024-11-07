import smartcard.System
from smartcard.util import toHexString

# Connect to the reader (ACS ACR122U)
readers = smartcard.System.readers()
if not readers:
    print("No NFC readers found")
    exit()

reader = readers[0]
connection = reader.createConnection()
connection.connect()

# List of APDUs to retrieve card data
# Note: Replace these APDUs with real values based on the card issuer's documentation
APDUs = {
    'SELECT_APP': [0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x00],  # AID
    'READ_CARD_NUMBER': [0x00, 0xB2, 0x01, 0x0C, 0x00],
    'READ_CARDHOLDER_NAME': [0x00, 0xB2, 0x02, 0x0C, 0x00],
    'READ_BRANCH': [0x00, 0xB2, 0x03, 0x0C, 0x00],
    'READ_CVV': [0x00, 0xB2, 0x04, 0x0C, 0x00],
    'READ_EXPIRY_DATE': [0x00, 0xB2, 0x05, 0x0C, 0x00]
}

# Function to transmit APDUs and handle responses
def send_apdu(apdu_command):
    response, sw1, sw2 = connection.transmit(apdu_command)
    if sw1 == 0x90 and sw2 == 0x00:
        return toHexString(response)
    else:
        print(f"Error: SW1={hex(sw1)}, SW2={hex(sw2)}")
        return None

# Select the application
print("Selecting application...")
response = send_apdu(APDUs['SELECT_APP'])
if response:
    print(f"Application selected successfully: {response}")

# Reading card details
card_details = {}

print("Reading card number...")
card_number = send_apdu(APDUs['READ_CARD_NUMBER'])
if card_number:
    card_details['Card Number'] = card_number
    print(f"Card Number: {card_number}")

print("Reading cardholder name...")
cardholder_name = send_apdu(APDUs['READ_CARDHOLDER_NAME'])
if cardholder_name:
    card_details['Card Holder Name'] = cardholder_name
    print(f"Card Holder Name: {cardholder_name}")

print("Reading branch...")
branch = send_apdu(APDUs['READ_BRANCH'])
if branch:
    card_details['Branch'] = branch
    print(f"Branch: {branch}")

print("Reading CVV...")
cvv = send_apdu(APDUs['READ_CVV'])
if cvv:
    card_details['CVV'] = cvv
    print(f"CVV: {cvv}")

print("Reading expiry date...")
expiry_date = send_apdu(APDUs['READ_EXPIRY_DATE'])
if expiry_date:
    card_details['Expiry Date'] = expiry_date
    print(f"Expiry Date: {expiry_date}")

print("\nFinal Card Details:")
for key, value in card_details.items():
    print(f"{key}: {value}")

