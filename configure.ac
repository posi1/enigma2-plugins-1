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

AC_ARG_WITH(arch,
	[  --with-arch=NAME box arch [[none,ah4,mipsel...]]],
	[ARCH="$withval"],[ARCH="mipsel"])
AC_SUBST(ARCH)
AC_DEFINE_UNQUOTED(ARCH,"$ARCH",[box arch])

AM_CONDITIONAL(SH4, test `echo "$ARCH" | cut -b 1-3` == "sh4")
AM_CONDITIONAL(MIPSEL, test `echo "$ARCH" | cut -b 1-6` == "mipsel")
AM_CONDITIONAL(ARM, test `echo "$ARCH" | cut -b 1-3` == "arm")

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

AC_ARG_WITH(debug,
	AS_HELP_STRING([--without-debug],[disable debugging code]),
	[with_debug="$withval"],[with_debug="yes"])
if test "$with_debug" = "yes"; then
	DEBUG_CFLAGS="-ggdb3"
	AC_DEFINE([DEBUG],[1],[Define to 1 to enable debugging code])
fi
AC_SUBST(DEBUG_CFLAGS)

AC_CONFIG_FILES([
Makefile

advancedmovieselection/Makefile
advancedmovieselection/meta/Makefile
advancedmovieselection/po/Makefile
advancedmovieselection/src/buttons/Makefile
advancedmovieselection/src/images/Makefile
advancedmovieselection/src/Makefile
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
aihdcontroler/src/comp/Makefile
aihdcontroler/src/data/Makefile
aihdcontroler/src/Makefile

antiscrollbar/Makefile
antiscrollbar/meta/Makefile
antiscrollbar/src/Makefile

aspectratioswitch/Makefile
aspectratioswitch/meta/Makefile
aspectratioswitch/po/Makefile
aspectratioswitch/src/Makefile

audiorestart/img/Makefile
audiorestart/Makefile
audiorestart/meta/Makefile
audiorestart/po/Makefile
audiorestart/src/Makefile

audiosync/img/Makefile
audiosync/Makefile
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
autotimer/src/web-data/Makefile
autotimer/src/web/Makefile
autotimer/src/WebScreens/Makefile

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

bmediacenter/Makefile
bmediacenter/meta/Makefile
bmediacenter/po/Makefile
bmediacenter/src/converter/Makefile
bmediacenter/src/icons/70x70/Makefile
bmediacenter/src/icons/Makefile
bmediacenter/src/Makefile
bmediacenter/src/radio/Makefile
bmediacenter/src/renderer/Makefile
bmediacenter/src/saver/Makefile
bmediacenter/src/skins/defaultHD/images/Makefile
bmediacenter/src/skins/defaultHD/Makefile
bmediacenter/src/skins/Makefile

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
eibox/src/images/Makefile
eibox/src/Makefile

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
epgbackup/src/localehelp/Makefile
epgbackup/src/Makefile

epgrefresh/Makefile
epgrefresh/meta/Makefile
epgrefresh/po/Makefile
epgrefresh/src/localehelp/Makefile
epgrefresh/src/Makefile

epgsearchpli/Makefile
epgsearchpli/meta/Makefile
epgsearchpli/po/Makefile
epgsearchpli/src/icons/Makefile
epgsearchpli/src/Makefile

esame/Makefile
esame/meta/Makefile
esame/src/data/Makefile
esame/src/Makefile

eventlist/Makefile
eventlist/src/Makefile

eventposition/Makefile
eventposition/src/Makefile

fancontrol2/Makefile
fancontrol2/meta/Makefile
fancontrol2/po/Makefile
fancontrol2/src/data/Makefile
fancontrol2/src/Makefile

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
fritzcall/src/images/Makefile
fritzcall/src/images/MODERN/Makefile
fritzcall/src/Makefile

fstabeditor/Makefile
fstabeditor/meta/Makefile
fstabeditor/src/Makefile

ftpbrowser/Makefile
ftpbrowser/meta/Makefile
ftpbrowser/po/Makefile
ftpbrowser/src/images/Makefile
ftpbrowser/src/Makefile

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

kiddytimer/img/Makefile
kiddytimer/Makefile
kiddytimer/meta/Makefile
kiddytimer/po/Makefile
kiddytimer/src/Makefile

lastfm/Makefile
lastfm/meta/Makefile
lastfm/po/Makefile
lastfm/src/Makefile

letterbox/Makefile
letterbox/meta/Makefile
letterbox/src/Makefile

logomanager/logodir_hdd/Makefile
logomanager/Makefile
logomanager/meta/Makefile
logomanager/src/Makefile

mediadownloader/Makefile
mediadownloader/meta/Makefile
mediadownloader/po/Makefile
mediadownloader/src/Makefile

menusort/Makefile
menusort/meta/Makefile
menusort/src/Makefile

merlinepgcenter/images/HD_BORDER/Makefile
merlinepgcenter/images/HD_Elgato/Makefile
merlinepgcenter/images/HD/Makefile
merlinepgcenter/images/Makefile
merlinepgcenter/images/SD/Makefile
merlinepgcenter/images/XD_BORDER/Makefile
merlinepgcenter/images/XD/Makefile
merlinepgcenter/Makefile
merlinepgcenter/meta/Makefile
merlinepgcenter/po/Makefile
merlinepgcenter/skins/Makefile
merlinepgcenter/src/Makefile

merlinepg/Makefile
merlinepg/meta/Makefile
merlinepg/src/Makefile

merlinmusicplayer/Makefile
merlinmusicplayer/meta/Makefile
merlinmusicplayer/po/Makefile
merlinmusicplayer/src/images/Makefile
merlinmusicplayer/src/Makefile

mosaic/Makefile
mosaic/meta/Makefile
mosaic/po/Makefile
mosaic/src/Makefile

moviecut/Makefile
moviecut/meta/Makefile
moviecut/po/Makefile
moviecut/src_cc/Makefile
moviecut/src/Makefile

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

movietagger/etc/Makefile
movietagger/Makefile
movietagger/meta/Makefile
movietagger/po/Makefile
movietagger/src/Makefile

mphelp/Makefile
mphelp/meta/Makefile
mphelp/po/Makefile
mphelp/src/Makefile

multirc/Makefile
multirc/meta/Makefile
multirc/src/Makefile

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
netcaster/src/bin/interface/Makefile
netcaster/src/bin/Makefile
netcaster/src/etc/Makefile
netcaster/src/Makefile

networkbrowserpli/Makefile
networkbrowserpli/meta/Makefile
networkbrowserpli/po/Makefile
networkbrowserpli/src/icons/Makefile
networkbrowserpli/src/lib/Makefile
networkbrowserpli/src/Makefile

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
partnerbox/src/icons/Makefile
partnerbox/src/Makefile

permanentclock/Makefile
permanentclock/meta/Makefile
permanentclock/po/Makefile
permanentclock/src/Makefile
permanentclock/src/trad/Makefile

pipservicerelation/Makefile
pipservicerelation/meta/Makefile
pipservicerelation/src/Makefile

pluginhider/Makefile
pluginhider/meta/Makefile
pluginhider/po/Makefile
pluginhider/src/Makefile

pluginsort/Makefile
pluginsort/meta/Makefile
pluginsort/po/Makefile
pluginsort/src/Makefile

podcast/etc/Makefile
podcast/Makefile
podcast/meta/Makefile
podcast/po/Makefile
podcast/src/Makefile

primetimemanager/Makefile
primetimemanager/meta/Makefile
primetimemanager/po/Makefile
primetimemanager/src/images/Makefile
primetimemanager/src/Makefile

pushservice/Makefile
pushservice/meta/Makefile
pushservice/po/Makefile
pushservice/src/Controller/Makefile
pushservice/src/Makefile
pushservice/src/Services/gntp/Makefile
pushservice/src/Services/mail/Makefile
pushservice/src/Services/Makefile

quickbutton/Makefile
quickbutton/meta/Makefile
quickbutton/po/Makefile
quickbutton/src/Makefile

reconstructapsc/Makefile
reconstructapsc/meta/Makefile
reconstructapsc/src/Makefile

recordinfobar/Makefile
recordinfobar/meta/Makefile
recordinfobar/po/Makefile
recordinfobar/src/Makefile

reftopiconname/Makefile
reftopiconname/src/Makefile

remotetimer/Makefile
remotetimer/meta/Makefile
remotetimer/src/Makefile

rsdownloader/Makefile
rsdownloader/meta/Makefile
rsdownloader/po/Makefile
rsdownloader/src/container/Makefile
rsdownloader/src/Makefile

satloader/Makefile
satloader/meta/Makefile
satloader/po/Makefile
satloader/src/Makefile

schiffe/Makefile
schiffe/meta/Makefile
schiffe/src/Makefile

seriesplugin/etc/Makefile
seriesplugin/Makefile
seriesplugin/meta/Makefile
seriesplugin/po/Makefile
seriesplugin/src/Identifiers/Makefile
seriesplugin/src/Images/Makefile
seriesplugin/src/Logos/Makefile
seriesplugin/src/Makefile
seriesplugin/src/Skins/Makefile

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
subsdownloader2/src/pic/buttons/HD/Makefile
subsdownloader2/src/pic/buttons/Makefile
subsdownloader2/src/pic/Makefile
subsdownloader2/src/pic/res/Makefile
subsdownloader2/src/SourceCode/chardet/Makefile
subsdownloader2/src/SourceCode/Makefile
subsdownloader2/src/SourceCode/periscope/Makefile
subsdownloader2/src/SourceCode/periscope/services/BierDopje/Makefile
subsdownloader2/src/SourceCode/periscope/services/Makefile
subsdownloader2/src/SourceCode/periscope/services/OpenSubtitle/Makefile
subsdownloader2/src/SourceCode/periscope/services/Subtitulos/Makefile
subsdownloader2/src/SourceCode/xbmc_subtitles/Makefile
subsdownloader2/src/SourceCode/xbmc_subtitles/services/Itasa/Makefile
subsdownloader2/src/SourceCode/xbmc_subtitles/services/Makefile

sudoku/Makefile
sudoku/meta/Makefile
sudoku/src/Makefile

svdrp/Makefile
svdrp/meta/Makefile
svdrp/src/Makefile

systemtime/Makefile
systemtime/meta/Makefile
systemtime/po/Makefile
systemtime/src/images/Makefile
systemtime/src/Makefile

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

transmission/Makefile
transmission/meta/Makefile
transmission/po/Makefile
transmission/src/Makefile

tvcharts/Makefile
tvcharts/meta/Makefile
tvcharts/src/Makefile

unwetterinfo/Makefile
unwetterinfo/meta/Makefile
unwetterinfo/src/Makefile

valixdcontrol/Makefile
valixdcontrol/meta/Makefile
valixdcontrol/src/comp/Makefile
valixdcontrol/src/data/Makefile
valixdcontrol/src/Makefile

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
vps/src/Makefile
vps/src/WebComponents/Makefile
vps/src/WebComponents/Sources/Makefile
vps/src/web-data/Makefile
vps/src/web/Makefile

weathercomponenthandler/Makefile
weathercomponenthandler/src/Makefile

weathercomponent/Makefile
weathercomponent/src/Makefile

weatherplugin/Makefile
weatherplugin/meta/Makefile
weatherplugin/po/Makefile
weatherplugin/src/icons/Makefile
weatherplugin/src/Makefile

webadmin/Makefile
webadmin/meta/Makefile
webadmin/src/Makefile
webadmin/src/mobile/Makefile
webadmin/src/WebChilds/Makefile
webadmin/src/WebComponents/Makefile
webadmin/src/WebComponents/Sources/Makefile
webadmin/src/web-data/img/Makefile
webadmin/src/web-data/Makefile
webadmin/src/web-data/tpl/Makefile
webadmin/src/web/Makefile
webadmin/src/WebScreens/Makefile

webbouqueteditor/Makefile
webbouqueteditor/meta/Makefile
webbouqueteditor/src/Makefile
webbouqueteditor/src/WebChilds/Makefile
webbouqueteditor/src/WebComponents/Makefile
webbouqueteditor/src/WebComponents/Sources/Makefile
webbouqueteditor/src/web-data/Makefile
webbouqueteditor/src/web/Makefile
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
