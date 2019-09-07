installdir = $(libdir)/enigma2/python/Plugins/Extensions/DreamExplorer

SUBDIRS = res

install_PYTHON = *.py

install_DATA = pyo2xml dreamexplorer.png

install-data-hook:
	chmod +x $(DESTDIR)$(installdir)/pyo2xml
