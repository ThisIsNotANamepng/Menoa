# For application-wide utils
import asyncio
import signal
from desktop_notifier import DesktopNotifier, Urgency, Button, ReplyField, DEFAULT_SOUND

def alert(type, title, text, location="desktop"):
    # Raises a notification of an alert, either in the app or on the desktop

    if location=="desktop": desktop_notification()



async def desktop_notification(title, text) -> None:
    notifier = DesktopNotifier(app_name="Menoa")

    await notifier.send(
        title=title,
        message=text,
        urgency=Urgency.Critical,
        sound=DEFAULT_SOUND,
    )

    # Run the event loop forever to respond to user interactions with the notification.

asyncio.run(desktop_notification("Julius Caesar", "Et Tu, Brutus?"))