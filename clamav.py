from clamav_utils import scan_path_streaming

for filepath, result in scan_path_streaming("/home/jack/Downloads"):
    print(f"{filepath}: {result}")
    # In GUI: update progress bar, show in a label/list, etc.

