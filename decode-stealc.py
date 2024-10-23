import yara
import pefile
import argparse
import struct
import json

RULE_SOURCE = """rule StealC
{
	meta:
		author = "Yung Binary"
		hash = "619751f5ed0a9716318092998f2e4561f27f7f429fe6103406ecf16e33837470"
	strings:
		$decode_1 = {
			6A ??
			68 ?? ?? ?? ??
			68 ?? ?? ?? ??
			E8 ?? ?? ?? ??
			83 C4 0C
			A3 ?? ?? ?? ??
		}
	
	condition:
		$decode_1
}"""

def yara_scan(raw_data):
    yara_rules = yara.compile(source=RULE_SOURCE)
    matches = yara_rules.match(data=raw_data)

    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                yield instance.offset

def xor_data(data, key):
    decoded = bytearray()
    for i in range(len(data)):
        decoded.append(data[i] ^ key[i])
    return decoded

MAX_STRING_SIZE = 100

def string_from_offset(data, offset):
    return data[offset : offset + MAX_STRING_SIZE].split(b"\0", 1)[0]

def main():
    parser = argparse.ArgumentParser(description='StealC C2 decoder')
    parser.add_argument('-f','--file', help='Path to unpacked StealC', required=True)
    args = parser.parse_args()

    with open(args.file, "rb") as f:
        filebuf = f.read()

    config_dict = {"C2": [], "Strings": []}

    pe = pefile.PE(data=filebuf, fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    for str_decode_offset in yara_scan(filebuf):
        str_size = int(filebuf[str_decode_offset + 1])
        # Ensure it's not a dummy string
        if not str_size:
            continue

        key_rva = filebuf[str_decode_offset + 3 : str_decode_offset + 7]
        encoded_str_rva = filebuf[str_decode_offset + 8 : str_decode_offset + 12]
        dword_rva = filebuf[str_decode_offset + 21 : str_decode_offset + 25]
        
        key_offset = pe.get_offset_from_rva(struct.unpack("i", key_rva)[0] - image_base)
        encoded_str_offset = pe.get_offset_from_rva(struct.unpack("i", encoded_str_rva)[0] - image_base)
        dword_offset = hex(struct.unpack("i", dword_rva)[0])[2:]
        dword_name = f"dword_{dword_offset}"

        key = string_from_offset(filebuf, key_offset)
        encoded_str = string_from_offset(filebuf, encoded_str_offset)
        
        decoded_str = xor_data(encoded_str, key).decode()
        if "http://" in decoded_str or "https://" in decoded_str:
            config_dict["C2"].append(decoded_str)
        else:
            config_dict["Strings"].append({f"dword_{dword_offset}" : decoded_str})
    
    print(json.dumps(config_dict, indent=4))

if __name__ == "__main__":
    main()
