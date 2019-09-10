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
	epgsearchpli \
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
	networkbrowserpli \
	ofdb \
	orfat \
	orfteletext \
	partnerbox \
	permanentclock \
	pipservicerelation \
	pluginhider \
	pluginsort \
	podcast \
	primetimemanager \
	pushservice \
	quickbutton \
	reconstructapsc \
	recordinfobar \
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
	systemtime \
	tageditor \
	teletext \
	toolkit \
	transmission \
	tvcharts \
	unwetterinfo \
	valixdcontrol \
	vfdcontrol \
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


metadir = $(datadir)/meta
meta_DATA = index-enigma2-plugins.xml
CLEANFILES = index-enigma2-plugins.xml

index-enigma2-plugins.xml: $(top_srcdir)/genmetaindex.py $(top_srcdir)/*/meta/plugin_*.xml
	$(AM_V_GEN)$(PYTHON) $^ > $@
