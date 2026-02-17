from setuptools import setup, find_packages

setup(
    name="filesnitch-ui",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "filesnitch-dbus",
        "PyGObject",
    ],
    entry_points={
        "gui_scripts": ["filesnitch-ui = filesnitch_ui.__main__:main"],
    },
)
