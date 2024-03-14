def hex_to_plaintext(hex_string):
    try:
        plaintext = bytearray.fromhex(hex_string).decode('utf-8')
        return plaintext
    except ValueError:
        return "Invalid hex string."

# Example usage:
hex_string = "48656c6c6f20576f726c64"  # Hex representation of "Hello World"
plaintext = hex_to_plaintext(hex_string)
print("Plaintext:", plaintext)