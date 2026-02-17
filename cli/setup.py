from setuptools import setup, find_packages

setup(
    name="filesnitch-cli",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "filesnitch-dbus",
        "click",
        "rich",
    ],
    entry_points={
        "console_scripts": ["filesnitch = filesnitch_cli.__main__:main"],
    },
)
