# For application-wide utils
import asyncio
import signal
from desktop_notifier import DesktopNotifier, Urgency, Button, ReplyField, DEFAULT_SOUND, Icon
from pathlib import Path

def alert(title, text, type="normal", location="desktop"):
    # Raises a notification of an alert, either in the app or on the desktop
    title=str(title)
    text=str(text)

    if location=="desktop": asyncio.run(desktop_notification(title, text)) #desktop_notification(title, text)


async def desktop_notification(title, text) -> None:
    notifier = DesktopNotifier(app_name="Menoa")
    icon_path = Path("/home/jack/code/LinuxSecuritySystem/gui/notification_icon.png")
    icon = Icon(path=icon_path)

    await notifier.send(
        title=title,
        message=text,
        urgency=Urgency.Critical,
        sound=DEFAULT_SOUND,
        icon=icon
    )

    # Run the event loop forever to respond to user interactions with the notification.