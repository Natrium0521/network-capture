def conv(data):
    def pb(b):
        hex_str = " ".join(f"{c:02x}" for c in b)
        if len(hex_str) > 23:
            hex_str = hex_str[:23] + " " + hex_str[23:]
        ascii_str = "".join(f'{chr(c) if 32 <= c <= 126 else "."}' for c in b)
        if len(ascii_str) > 8:
            ascii_str = ascii_str[:8] + " " + ascii_str[8:]
        return f"{hex_str:<48} | {ascii_str}\n"

    rets = ""
    arr = []
    for i in data:
        arr.append(i)
        if len(arr) == 16:
            rets += pb(arr)
            arr = []
    if len(arr):
        pb(arr)
        
    return rets
