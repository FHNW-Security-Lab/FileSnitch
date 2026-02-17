{ lib, python3Packages, wrapGAppsHook4, gobject-introspection, gtk4, libadwaita }:

python3Packages.buildPythonApplication rec {
  pname = "filesnitch-ui";
  version = "0.1.0";
  format = "setuptools";

  src = ../ui;

  nativeBuildInputs = [
    wrapGAppsHook4
    gobject-introspection
  ];

  buildInputs = [
    gtk4
    libadwaita
  ];

  propagatedBuildInputs = with python3Packages; [
    pygobject3
    dasbus
    (buildPythonPackage rec {
      pname = "filesnitch-dbus";
      version = "0.1.0";
      format = "setuptools";
      src = ../shared;
      propagatedBuildInputs = [ dasbus ];
    })
  ];

  # No tests to run
  doCheck = false;

  # Don't wrap twice (wrapGAppsHook4 handles it)
  dontWrapGApps = true;
  preFixup = ''
    makeWrapperArgs+=("''${gappsWrapperArgs[@]}")
  '';

  meta = with lib; {
    description = "FileSnitch GTK4 user interface";
    license = licenses.gpl3;
    platforms = platforms.linux;
  };
}
