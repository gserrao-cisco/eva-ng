from eva import app
from eva import modules

@app.command()
def list():
    """
    List all available modules
    """
    print("Available modules:")
    for mod_name, module in modules.items():
        print(f" - {mod_name}: {module}")

