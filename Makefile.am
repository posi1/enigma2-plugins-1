ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	advancedmovieselection \
	advhdmi \
	aihdcontroler \
	antiscrollbar \
	aspectratioswitch \
	audiorestart \
	audiosync \
	automaticcleanup \
	automaticvolumeadjustment \
	autoresolution \
	autotimer \
	babelzapper \
	birthdayreminder \
	bmediacenter \
	bonjour \
	cdinfo \
	channelselectionshorttitle \
	curlytx \
	dreamexplorer \
	dreamirc \
	dreammediathek \
	dvdbackup \
	easyinfo \
	easymedia \
	ecasa \
	eibox \
	emailclient \
	emission \
	eparted \
	epgrefresh \
	epgsearch \
	esame \
	eventlist \
	eventposition \
	fancontrol2 \
	filebrowser \
	flashexpander \
	fritzcall \
	fstabeditor \
	ftpbrowser \
	googlemaps \
	growlee \
	imdb \
	infobartunerstate \
	kiddytimer \
	letterbox \
	logomanager \
	mediadownloader \
	menusort \
	merlinepg \
	merlinepgcenter \
	merlinmusicplayer \
	mosaic \
	moviecut \
	movielistpreview \
	movieretitle \
	moviesearch \
	movietagger \
	mphelp \
	multirc \
	mytube \
	ncidclient \
	netcaster \
	networkbrowser \
	ofdb \
	orfat \
	orfteletext \
	partnerbox \
	permanentclock \
	pipservicerelation \
	pluginhider \
	pluginsort \
	podcast \
	pushservice \
	quickbutton \
	reconstructapsc \
	reftopiconname \
	remotetimer \
	rsdownloader \
	schiffe \
	seriesplugin \
	setpasswd \
	shoutcast \
	showclock \
	simplerss \
	subsdownloader2 \
	sudoku \
	svdrp \
	tageditor \
	teletext \
	toolkit \
	tvcharts \
	unwetterinfo \
	valixdcontrol \
	videocolorspace \
	vierg \
	vlcplayer \
	vps \
	weathercomponent \
	weathercomponenthandler \
	weatherplugin \
	webadmin \
	webbouqueteditor \
	webcamviewer \
	werbezapper \
	yttrailer \
	zaphistorybrowser \
	zapstatistic \
	zdfmediathek


# epgsearchpli networkbrowserpli (PLi)

metadir = $(datadir)/meta
meta_DATA = index-enigma2-plugins.xml
CLEANFILES = index-enigma2-plugins.xml

index-enigma2-plugins.xml: $(top_srcdir)/genmetaindex.py $(top_srcdir)/*/meta/plugin_*.xml
	$(AM_V_GEN)$(PYTHON) $^ > $@
