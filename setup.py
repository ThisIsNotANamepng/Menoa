from setuptools import setup, find_packages

setup(
    name="menoa",
    version="0.4.5",
    packages=find_packages(),
    install_requires=[
        "requests>=0.1.0",
        # Add dependencies here (e.g., "PyQt5>=5.15")
    ],
    package_data={
        "menoa": [
            "dark_style.qss",
            "light_style.qss",
            "notification_icon.png",
            "utils/*.py",
            "pages/*.py"
        ],
    },
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "menoa=menoa.cli:main",
        ],
        "gui_scripts": [
            "menoa-gui=menoa.main:main",
        ],
    },
)
