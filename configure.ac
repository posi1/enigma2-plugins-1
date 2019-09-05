AC_INIT([enigma2-plugins],[3.2.0],[enigma2-devel@lists.elitedvb.net])
AM_INIT_AUTOMAKE([dist-bzip2 foreign no-define tar-pax])
AC_CONFIG_HEADERS([enigma2-plugins-config.h])

# Silent rules are available since 1.11, but older versions
# are still in use. So don't use them unconditionally.
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

AC_PROG_CC
AC_PROG_CXX
m4_ifdef([LT_INIT], [LT_INIT], [AC_PROG_LIBTOOL])
AC_CONFIG_MACRO_DIR([m4])

AC_CHECK_HEADERS([dbox/fp.h dbox/lcd-ks0713.h])

AC_PATH_PROG(MSGFMT, msgfmt, AC_MSG_ERROR(Could not find msgfmt))
AC_PATH_PROG(MSGINIT, msginit, AC_MSG_ERROR(Could not find msginit))
AC_PATH_PROG(MSGMERGE, msgmerge, AC_MSG_ERROR(Could not find msgmerge))
AC_PATH_PROG(MSGUNIQ, msguniq, AC_MSG_ERROR(Could not find msguniq))
AC_PATH_PROG(XGETTEXT, xgettext, AC_MSG_ERROR(Could not find xgettext))

AM_PATH_PYTHON
AX_PYTHON_DEVEL
AX_PTHREAD

#dnl versions of gstreamer and plugins-base
AC_ARG_WITH(gstversion,
	AS_HELP_STRING([--with-gstversion],[use gstreamer version (major.minor)]),
	[GST_MAJORMINOR=$withval],[GST_MAJORMINOR=0.10])

AC_ARG_WITH(boxtype,
	[  --with-boxtype=NAME box type [[none,dm800...]]],
	[BOXTYPE="$withval"],[BOXTYPE="dm800"])
AC_SUBST(BOXTYPE)
AC_DEFINE_UNQUOTED(BOXTYPE,"$BOXTYPE",[box type])

AC_ARG_WITH(boxbrand,
	[  --with-boxbrand=NAME box brand [[none,dreambox...]]],
	[BOXBRAND="$withval"],[BOXBRAND="dreambox"])
AC_SUBST(BOXBRAND)
AC_DEFINE_UNQUOTED(BOXBRAND,"$BOXBRAND",[box brand])

PKG_CHECK_MODULES(ENIGMA2, enigma2)
PKG_CHECK_MODULES(GSTREAMER, gstreamer-$GST_MAJORMINOR gstreamer-pbutils-$GST_MAJORMINOR)
PKG_CHECK_MODULES(LIBCRYPTO, libcrypto)

AC_ARG_WITH(debug,
	AS_HELP_STRING([--without-debug],[disable debugging code]),
	[with_debug="$withval"],[with_debug="yes"])
if test "$with_debug" = "yes"; then
	DEBUG_CFLAGS="-ggdb3"
	AC_DEFINE([DEBUG],[1],[Define to 1 to enable debugging code])
fi
AC_SUBST(DEBUG_CFLAGS)

AC_ARG_WITH(po,
	AS_HELP_STRING([--with-po],[enable updating of po files]),
	[with_po="$withval"],[with_po="no"])
if test "$with_po" = "yes"; then
	AC_PATH_PROG(MSGINIT, msginit)
	AC_PATH_PROG(MSGMERGE, msgmerge)
	AC_PATH_PROG(MSGUNIQ, msguniq)
	AC_PATH_PROG(XGETTEXT, xgettext)
	if test -z "$MSGINIT" -o -z "$MSGMERGE" -o -z "$MSGUNIQ" -o -z "$XGETTEXT"; then
		AC_MSG_ERROR([Could not find required gettext tools])
	fi
fi
AM_CONDITIONAL(UPDATE_PO, test "$with_po" = "yes")

AC_CONFIG_FILES([
Makefile

advancedmovieselection/Makefile
advancedmovieselection/meta/Makefile
advancedmovieselection/po/Makefile
advancedmovieselection/src/Makefile
advancedmovieselection/src/buttons/Makefile
advancedmovieselection/src/images/Makefile
advancedmovieselection/src/skin/Makefile
advancedmovieselection/src/Source/Makefile
advancedmovieselection/src/Source/MovieDB/Makefile
advancedmovieselection/src/Source/MovieDB/tmdb3/Makefile
advancedmovieselection/src/Source/Remote/Makefile

advhdmi/Makefile
advhdmi/meta/Makefile
advhdmi/po/Makefile
advhdmi/src/Makefile

aihdcontroler/Makefile
aihdcontroler/meta/Makefile
aihdcontroler/src/Makefile
aihdcontroler/src/comp/Makefile
aihdcontroler/src/data/Makefile

antiscrollbar/Makefile
antiscrollbar/meta/Makefile
antiscrollbar/src/Makefile

aspectratioswitch/Makefile
aspectratioswitch/meta/Makefile
aspectratioswitch/po/Makefile
aspectratioswitch/src/Makefile

audiorestart/Makefile
audiorestart/img/Makefile
audiorestart/meta/Makefile
audiorestart/po/Makefile
audiorestart/src/Makefile

audiosync/Makefile
audiosync/img/Makefile
audiosync/meta/Makefile
audiosync/po/Makefile
audiosync/src/Makefile

automaticcleanup/Makefile
automaticcleanup/meta/Makefile
automaticcleanup/po/Makefile
automaticcleanup/src/Makefile

automaticvolumeadjustment/Makefile
automaticvolumeadjustment/meta/Makefile
automaticvolumeadjustment/po/Makefile
automaticvolumeadjustment/src/Makefile

autoresolution/Makefile
autoresolution/meta/Makefile
autoresolution/po/Makefile
autoresolution/src/Makefile

autotimer/etc/Makefile
autotimer/Makefile
autotimer/meta/Makefile
autotimer/po/Makefile
autotimer/src/Makefile
autotimer/src/WebChilds/Makefile
autotimer/src/WebComponents/Makefile
autotimer/src/WebComponents/Sources/Makefile
autotimer/src/WebScreens/Makefile
autotimer/src/web/Makefile
autotimer/src/web-data/Makefile

babelzapper/etc/Makefile
babelzapper/Makefile
babelzapper/meta/Makefile
babelzapper/src/Makefile

birthdayreminder/Makefile
birthdayreminder/meta/Makefile
birthdayreminder/po/Makefile
birthdayreminder/src/Makefile

bitrateviewer/Makefile
bitrateviewer/meta/Makefile
bitrateviewer/src/Makefile
bitrateviewer/src/bitratecalc/Makefile

bmediacenter/Makefile
bmediacenter/meta/Makefile
bmediacenter/po/Makefile
bmediacenter/src/Makefile
bmediacenter/src/icons/Makefile
bmediacenter/src/icons/70x70/Makefile
bmediacenter/src/converter/Makefile
bmediacenter/src/renderer/Makefile
bmediacenter/src/radio/Makefile
bmediacenter/src/saver/Makefile
bmediacenter/src/skins/Makefile
bmediacenter/src/skins/defaultHD/Makefile
bmediacenter/src/skins/defaultHD/images/Makefile

bonjour/Makefile
bonjour/meta/Makefile
bonjour/src/Makefile

cdinfo/Makefile
cdinfo/meta/Makefile
cdinfo/src/Makefile

channelselectionshorttitle/Makefile
channelselectionshorttitle/src/Makefile

curlytx/Makefile
curlytx/meta/Makefile
curlytx/po/Makefile
curlytx/src/Makefile

dreamexplorer/Makefile
dreamexplorer/meta/Makefile
dreamexplorer/src/Makefile
dreamexplorer/src/res/Makefile

dreamirc/Makefile
dreamirc/meta/Makefile
dreamirc/src/Makefile
dreamirc/src/protocols/Makefile

dreammediathek/Makefile
dreammediathek/src/Makefile

dvdbackup/Makefile
dvdbackup/meta/Makefile
dvdbackup/po/Makefile
dvdbackup/src/Makefile

easyinfo/Makefile
easyinfo/meta/Makefile
easyinfo/src/Makefile

easymedia/Makefile
easymedia/meta/Makefile
easymedia/po/Makefile
easymedia/src/Makefile

ecasa/Makefile
ecasa/meta/Makefile
ecasa/src/Makefile

eibox/Makefile
eibox/meta/Makefile
eibox/po/Makefile
eibox/src/Makefile
eibox/src/images/Makefile

elektro/Makefile
elektro/meta/Makefile
elektro/po/Makefile
elektro/src/Makefile

emailclient/Makefile
emailclient/meta/Makefile
emailclient/po/Makefile
emailclient/src/Makefile

emission/Makefile
emission/meta/Makefile
emission/src/Makefile

eparted/Makefile
eparted/meta/Makefile
eparted/po/Makefile
eparted/src/Makefile

epgbackup/Makefile
epgbackup/meta/Makefile
epgbackup/po/Makefile
epgbackup/src/Makefile
epgbackup/src/localehelp/Makefile

epgrefresh/Makefile
epgrefresh/meta/Makefile
epgrefresh/po/Makefile
epgrefresh/src/Makefile
epgrefresh/src/localehelp/Makefile

esame/Makefile
esame/meta/Makefile
esame/src/Makefile
esame/src/data/Makefile

epgsearch/Makefile
epgsearch/meta/Makefile
epgsearch/po/Makefile
epgsearch/src/Makefile

eventlist/Makefile
eventlist/src/Makefile

eventposition/Makefile
eventposition/src/Makefile

fancontrol2/Makefile
fancontrol2/meta/Makefile
fancontrol2/po/Makefile
fancontrol2/src/Makefile
fancontrol2/src/data/Makefile

filebrowser/Makefile
filebrowser/meta/Makefile
filebrowser/src/Makefile

flashexpander/Makefile
flashexpander/meta/Makefile
flashexpander/po/Makefile
flashexpander/src/Makefile

fritzcall/Makefile
fritzcall/meta/Makefile
fritzcall/po/Makefile
fritzcall/src/Makefile
fritzcall/src/images/Makefile
fritzcall/src/images/MODERN/Makefile

fstabeditor/Makefile
fstabeditor/meta/Makefile
fstabeditor/src/Makefile

ftpbrowser/Makefile
ftpbrowser/meta/Makefile
ftpbrowser/po/Makefile
ftpbrowser/src/Makefile
ftpbrowser/src/images/Makefile

googlemaps/Makefile
googlemaps/meta/Makefile
googlemaps/src/Makefile

growlee/Makefile
growlee/meta/Makefile
growlee/src/Makefile

httpproxy/Makefile
httpproxy/meta/Makefile
httpproxy/src/Makefile

imdb/Makefile
imdb/meta/Makefile
imdb/po/Makefile
imdb/src/Makefile

infobartunerstate/Makefile
infobartunerstate/meta/Makefile
infobartunerstate/po/Makefile
infobartunerstate/src/Makefile

kiddytimer/Makefile
kiddytimer/img/Makefile
kiddytimer/meta/Makefile
kiddytimer/po/Makefile
kiddytimer/src/Makefile

lastfm/Makefile
lastfm/meta/Makefile
lastfm/po/Makefile
lastfm/src/Makefile

letterbox/Makefile
letterbox/src/Makefile
letterbox/meta/Makefile

logomanager/Makefile
logomanager/logodir_hdd/Makefile
logomanager/meta/Makefile
logomanager/src/Makefile

mediadownloader/Makefile
mediadownloader/meta/Makefile
mediadownloader/po/Makefile
mediadownloader/src/Makefile

menusort/Makefile
menusort/meta/Makefile
menusort/src/Makefile

merlinepg/Makefile
merlinepg/meta/Makefile
merlinepg/src/Makefile

merlinepgcenter/Makefile
merlinepgcenter/meta/Makefile
merlinepgcenter/src/Makefile
merlinepgcenter/po/Makefile
merlinepgcenter/skins/Makefile
merlinepgcenter/images/Makefile
merlinepgcenter/images/HD/Makefile
merlinepgcenter/images/HD_BORDER/Makefile
merlinepgcenter/images/SD/Makefile
merlinepgcenter/images/XD/Makefile
merlinepgcenter/images/XD_BORDER/Makefile
merlinepgcenter/images/HD_Elgato/Makefile

merlinmusicplayer/Makefile
merlinmusicplayer/meta/Makefile
merlinmusicplayer/po/Makefile
merlinmusicplayer/src/Makefile
merlinmusicplayer/src/images/Makefile

mosaic/Makefile
mosaic/meta/Makefile
mosaic/po/Makefile
mosaic/src/Makefile

moviecut/Makefile
moviecut/meta/Makefile
moviecut/po/Makefile
moviecut/src_cc/Makefile
moviecut/src_py/Makefile

movielistpreview/Makefile
movielistpreview/meta/Makefile
movielistpreview/po/Makefile
movielistpreview/src/Makefile

movieretitle/Makefile
movieretitle/meta/Makefile
movieretitle/po/Makefile
movieretitle/src/Makefile

moviesearch/Makefile
moviesearch/meta/Makefile
moviesearch/src/Makefile

movieselectionquickbutton/Makefile
movieselectionquickbutton/meta/Makefile
movieselectionquickbutton/po/Makefile
movieselectionquickbutton/src/Makefile

movietagger/Makefile
movietagger/etc/Makefile
movietagger/meta/Makefile
movietagger/po/Makefile
movietagger/src/Makefile

mphelp/Makefile
mphelp/meta/Makefile
mphelp/po/Makefile
mphelp/src/Makefile

multirc/Makefile
multirc/src/Makefile
multirc/meta/Makefile

mytube/Makefile
mytube/meta/Makefile
mytube/po/Makefile
mytube/src/Makefile

ncidclient/Makefile
ncidclient/meta/Makefile
ncidclient/po/Makefile
ncidclient/src/Makefile

netcaster/Makefile
netcaster/meta/Makefile
netcaster/src/Makefile
netcaster/src/bin/Makefile
netcaster/src/bin/interface/Makefile
netcaster/src/etc/Makefile

networkbrowser/Makefile
networkbrowser/meta/Makefile
networkbrowser/src/Makefile
networkbrowser/src/icons/Makefile
networkbrowser/src/lib/Makefile
networkbrowser/po/Makefile

ofdb/Makefile
ofdb/meta/Makefile
ofdb/po/Makefile
ofdb/src/Makefile

orfat/Makefile
orfat/meta/Makefile
orfat/src/Makefile

orfteletext/Makefile
orfteletext/meta/Makefile
orfteletext/src/Makefile

partnerbox/Makefile
partnerbox/meta/Makefile
partnerbox/po/Makefile
partnerbox/src/Makefile
partnerbox/src/icons/Makefile

permanentclock/Makefile
permanentclock/meta/Makefile
permanentclock/po/Makefile
permanentclock/src/Makefile
permanentclock/src/trad/Makefile

pipservicerelation/Makefile
pipservicerelation/src/Makefile
pipservicerelation/meta/Makefile

pluginhider/Makefile
pluginhider/meta/Makefile
pluginhider/po/Makefile
pluginhider/src/Makefile

pluginsort/Makefile
pluginsort/meta/Makefile
pluginsort/po/Makefile
pluginsort/src/Makefile

podcast/Makefile
podcast/etc/Makefile
podcast/meta/Makefile
podcast/po/Makefile
podcast/src/Makefile

pushservice/Makefile
pushservice/meta/Makefile
pushservice/po/Makefile
pushservice/src/Makefile
pushservice/src/Controller/Makefile
pushservice/src/Services/Makefile
pushservice/src/Services/gntp/Makefile
pushservice/src/Services/mail/Makefile

quickbutton/Makefile
quickbutton/meta/Makefile
quickbutton/po/Makefile
quickbutton/src/Makefile

reconstructapsc/Makefile
reconstructapsc/meta/Makefile
reconstructapsc/src_py/Makefile

reftopiconname/Makefile
reftopiconname/src/Makefile

remotetimer/Makefile
remotetimer/meta/Makefile
remotetimer/src/Makefile

rsdownloader/Makefile
rsdownloader/meta/Makefile
rsdownloader/po/Makefile
rsdownloader/src/Makefile
rsdownloader/src/container/Makefile

satloader/Makefile
satloader/meta/Makefile
satloader/src/Makefile
satloader/po/Makefile

schiffe/Makefile
schiffe/meta/Makefile
schiffe/src/Makefile

seriesplugin/Makefile
seriesplugin/etc/Makefile
seriesplugin/meta/Makefile
seriesplugin/po/Makefile
seriesplugin/src/Makefile
seriesplugin/src/Images/Makefile
seriesplugin/src/Logos/Makefile
seriesplugin/src/Skins/Makefile
seriesplugin/src/Identifiers/Makefile

setpasswd/Makefile
setpasswd/meta/Makefile
setpasswd/po/Makefile
setpasswd/src/Makefile

shoutcast/Makefile
shoutcast/meta/Makefile
shoutcast/po/Makefile
shoutcast/src/Makefile

showclock/Makefile
showclock/meta/Makefile
showclock/po/Makefile
showclock/src/Makefile

simplerss/Makefile
simplerss/meta/Makefile
simplerss/po/Makefile
simplerss/src/Makefile

subsdownloader2/Makefile
subsdownloader2/meta/Makefile
subsdownloader2/src/Makefile
subsdownloader2/src/pic/Makefile
subsdownloader2/src/pic/buttons/Makefile
subsdownloader2/src/pic/buttons/HD/Makefile
subsdownloader2/src/pic/res/Makefile
subsdownloader2/src/SourceCode/Makefile
subsdownloader2/src/SourceCode/chardet/Makefile
subsdownloader2/src/SourceCode/periscope/Makefile
subsdownloader2/src/SourceCode/periscope/services/Makefile
subsdownloader2/src/SourceCode/periscope/services/BierDopje/Makefile
subsdownloader2/src/SourceCode/periscope/services/OpenSubtitle/Makefile
subsdownloader2/src/SourceCode/periscope/services/Subtitulos/Makefile
subsdownloader2/src/SourceCode/xbmc_subtitles/Makefile
subsdownloader2/src/SourceCode/xbmc_subtitles/services/Makefile
subsdownloader2/src/SourceCode/xbmc_subtitles/services/Itasa/Makefile

sudoku/Makefile
sudoku/meta/Makefile
sudoku/src/Makefile

svdrp/Makefile
svdrp/meta/Makefile
svdrp/src/Makefile

tageditor/Makefile
tageditor/meta/Makefile
tageditor/po/Makefile
tageditor/src/Makefile

teletext/Makefile
teletext/meta/Makefile
teletext/po/Makefile
teletext/src/Makefile

toolkit/Makefile
toolkit/src/Makefile

tvcharts/Makefile
tvcharts/meta/Makefile
tvcharts/src/Makefile

unwetterinfo/Makefile
unwetterinfo/meta/Makefile
unwetterinfo/src/Makefile

valixdcontrol/Makefile
valixdcontrol/meta/Makefile
valixdcontrol/src/Makefile
valixdcontrol/src/comp/Makefile
valixdcontrol/src/data/Makefile

videocolorspace/Makefile
videocolorspace/meta/Makefile
videocolorspace/po/Makefile
videocolorspace/src/Makefile

vierg/Makefile
vierg/meta/Makefile
vierg/src/Makefile

vlcplayer/Makefile
vlcplayer/meta/Makefile
vlcplayer/po/Makefile
vlcplayer/src/Makefile

vps/Makefile
vps/meta/Makefile
vps/po/Makefile
vps/src_cc/Makefile
vps/src_py/Makefile
vps/src_py/web/Makefile
vps/src_py/web-data/Makefile
vps/src_py/WebComponents/Makefile
vps/src_py/WebComponents/Sources/Makefile

weatherplugin/Makefile
weatherplugin/meta/Makefile
weatherplugin/po/Makefile
weatherplugin/src/Makefile
weatherplugin/src/icons/Makefile

weathercomponent/Makefile
weathercomponent/src/Makefile

weathercomponenthandler/Makefile
weathercomponenthandler/src/Makefile


webadmin/Makefile
webadmin/meta/Makefile
webadmin/src/Makefile
webadmin/src/mobile/Makefile
webadmin/src/web/Makefile
webadmin/src/WebChilds/Makefile
webadmin/src/WebComponents/Makefile
webadmin/src/WebComponents/Sources/Makefile
webadmin/src/web-data/Makefile
webadmin/src/web-data/tpl/Makefile
webadmin/src/web-data/img/Makefile
webadmin/src/WebScreens/Makefile

webbouqueteditor/Makefile
webbouqueteditor/meta/Makefile
webbouqueteditor/src/Makefile
webbouqueteditor/src/web/Makefile
webbouqueteditor/src/web-data/Makefile
webbouqueteditor/src/WebChilds/Makefile
webbouqueteditor/src/WebComponents/Makefile
webbouqueteditor/src/WebComponents/Sources/Makefile
webbouqueteditor/src/WebScreens/Makefile

webcamviewer/Makefile
webcamviewer/meta/Makefile
webcamviewer/src/Makefile

werbezapper/Makefile
werbezapper/meta/Makefile
werbezapper/po/Makefile
werbezapper/src/Makefile

youtubeplayer/Makefile
youtubeplayer/meta/Makefile
youtubeplayer/src/Makefile
youtubeplayer/src/Nemesis.GlassLine_Mod/Makefile

yttrailer/Makefile
yttrailer/meta/Makefile
yttrailer/po/Makefile
yttrailer/src/Makefile

zaphistorybrowser/Makefile
zaphistorybrowser/meta/Makefile
zaphistorybrowser/po/Makefile
zaphistorybrowser/src/Makefile

zapstatistic/Makefile
zapstatistic/meta/Makefile
zapstatistic/po/Makefile
zapstatistic/src/Makefile

zdfmediathek/Makefile
zdfmediathek/meta/Makefile
zdfmediathek/src/Makefile

])
AC_OUTPUT
