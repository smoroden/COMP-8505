# ThreadedNotifier example from tutorial
#
# See: http://github.com/seb-m/pyinotify/wiki/Tutorial
#
import pyinotify

list = []
wm = pyinotify.WatchManager()  # Watch Manager
mask = pyinotify.IN_DELETE | pyinotify.IN_CREATE  # watched events

class EventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event):
        print "Creating:", event.pathname

    def process_IN_DELETE(self, event):
        print "Removing:", event.pathname


#log.setLevel(10)
notifier = pyinotify.ThreadedNotifier(wm, EventHandler())
notifier.start()

list.append(wm.add_watch('/tmp', mask, rec=True))
list.append(wm.add_watch('/temp', mask, rec=True))

for i in list:
    print i.keys()[0]
