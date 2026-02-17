{ lib, python3Packages }:

python3Packages.buildPythonApplication rec {
  pname = "filesnitch-cli";
  version = "0.1.0";
  format = "setuptools";

  src = ../cli;

  propagatedBuildInputs = with python3Packages; [
    click
    rich
    dasbus
    pygobject3
    (buildPythonPackage rec {
      pname = "filesnitch-dbus";
      version = "0.1.0";
      format = "setuptools";
      src = ../shared;
      propagatedBuildInputs = [ dasbus ];
    })
  ];

  # No tests
  doCheck = false;

  meta = with lib; {
    description = "FileSnitch command-line interface";
    license = licenses.gpl3;
    platforms = platforms.linux;
  };
}
