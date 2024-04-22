def save_file(content, file_path):
    with open(file_path, "wb") as f:
        f.write(content)

def load_file(file_path):
    with open(file_path, "rb") as f:
        content = f.read()
    return content