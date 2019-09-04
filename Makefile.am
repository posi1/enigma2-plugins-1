ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
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
	eventlist \
	eventposition \
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
	mediadownloader \
	merlinepg \
	merlinepgcenter \
	merlinmusicplayer \
	mosaic \
	moviecut \
	movieretitle \
	moviesearch \
	movietagger \
	mphelp \
	multirc \
	ncidclient \
	netcaster \
	ofdb \
	orfat \
	orfteletext \
	partnerbox \
	permanentclock \
	pipservicerelation \
	podcast \
	pushservice \
	quickbutton \
	reconstructapsc \
	reftopiconname \
	remotetimer \
	rsdownloader \
	seriesplugin \
	setpasswd \
	shoutcast \
	showclock \
	simplerss \
	subsdownloader2 \
	svdrp \
	tageditor \
	teletext \
	toolkit \
	tvcharts \
	unwetterinfo \
	valixdcontrol \
	videocolorspace \
	vlcplayer \
	vps \
	weatherplugin \
	weathercomponent \
	weathercomponenthandler \
	webadmin \
	webbouqueteditor \
	webcamviewer \
	werbezapper \
	zaphistorybrowser \
	zapstatistic \
	zdfmediathek \
	esame \
	schiffe \
	sudoku \
	vierg \
	bmediacenter \
	advancedmovieselection \
	fancontrol2 \
	logomanager \
	movielistpreview \
	networkbrowser \
	epgsearch \
	menusort \
	pluginhider \
	pluginsort \
	mytube \
	yttrailer


# webinterface (We use Open WebIF)
# networkbrowserpli epgsearchpli (PLi)

metadir = $(datadir)/meta
meta_DATA = index-enigma2-plugins.xml
CLEANFILES = index-enigma2-plugins.xml

index-enigma2-plugins.xml: $(top_srcdir)/genmetaindex.py $(top_srcdir)/*/meta/plugin_*.xml
	$(AM_V_GEN)$(PYTHON) $^ > $@
