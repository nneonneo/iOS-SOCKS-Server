#!python3
# Pretty statistics view originally by @philrosenthal.

import asyncio
import logging
import sys
import time

if "Pythonista" in sys.executable:
    import console


class ThroughputTracker:
    def __init__(self, smoothing: float = 0.5):
        self._smoothing = smoothing
        self._window = 0
        self._average = 0.0
        self._total = 0
        self._last_update = time.time()

    def add(self, amount: int) -> None:
        self._window += amount

    def update(self) -> tuple[float, int]:
        now = time.time()
        duration = now - self._last_update
        if duration < 0.1:
            return (self._average, self._total)

        self._last_update = now
        new_speed = self._window / duration
        smoothing = self._smoothing**duration
        self._average = smoothing * self._average + (1 - smoothing) * new_speed
        self._total += self._window
        self._window = 0
        return (self._average, self._total)


class TrafficStats:
    def add_inbound(self, nbytes: int) -> None:
        ...

    def add_outbound(self, nbytes: int) -> None:
        ...

    def add_connection(self) -> None:
        ...

    def remove_connection(self) -> None:
        ...


class SimpleTrafficStats(TrafficStats):
    def __init__(self) -> None:
        self.inbound = 0
        self.outbound = 0
        self.connections = 0

    def add_inbound(self, nbytes: int) -> None:
        self.inbound += nbytes

    def add_outbound(self, nbytes: int) -> None:
        self.outbound += nbytes

    def add_connection(self) -> None:
        self.connections += 1

    def remove_connection(self) -> None:
        self.connections -= 1


class StatusMonitor(TrafficStats, logging.Handler):
    def __init__(
        self,
        banner: str,
        interval: float = 1,
        smoothing: float = 0.5,
        log_level: int = logging.NOTSET,
    ):
        logging.Handler.__init__(self, log_level)
        self.banner = banner
        self.interval = interval
        self.inbound = ThroughputTracker(smoothing)
        self.outbound = ThroughputTracker(smoothing)
        self.num_connections = 0
        self.messages: list[str] = []
        self.num_errors = 0

    def add_inbound(self, nbytes: int) -> None:
        self.inbound.add(nbytes)

    def add_outbound(self, nbytes: int) -> None:
        self.outbound.add(nbytes)

    def add_connection(self) -> None:
        self.num_connections += 1

    def remove_connection(self) -> None:
        self.num_connections -= 1

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(self.format(record))
        if len(self.messages) > 5:
            self.messages = self.messages[-5:]
        if record.levelno >= logging.ERROR:
            self.num_errors += 1

    async def render_forever(self) -> None:
        while True:
            await asyncio.sleep(self.interval)

            # Clear the console
            if "Pythonista" in sys.executable:
                console.clear()
            else:
                print("\033c", end="")

            print(self.banner)

            inbound_average, inbound_total = self.inbound.update()
            outbound_average, outbound_total = self.outbound.update()
            megabit = 1024 * 1024 / 8
            megabyte = 1024 * 1024

            # Print the table
            print(f"{'Direction':<12} | {'Traffic (Mbps)':<15}")
            print(f"{'-'*12} | {'-'*15}")
            print(f"{'In':<12} | {inbound_average / megabit:<15.2f}")
            print(f"{'Out':<12} | {outbound_average / megabit:<15.2f}")
            # Print a blank line
            print()
            print(f"{'Connections:':<12} {self.num_connections:>6}")
            print(f"{'Total In:':<12} {inbound_total / megabyte:>6.2f} MB")
            print(f"{'Total Out:':<12} {outbound_total / megabyte:>6.2f} MB")
            print(
                f"{'Total:':<12} {(inbound_total + outbound_total) / megabyte:>6.2f} MB"
            )
            print()
            if self.num_errors:
                print(f"Errors: {self.num_errors}")
            if self.messages:
                print("Last 5 log messages:")
                for msg in self.messages:
                    print(f"    {msg}")


if __name__ == "__main__":
    import random

    stats = StatusMonitor("Test mode", interval=1)
    logging.getLogger().addHandler(stats)

    async def random_traffic() -> None:
        stats.add_connection()
        while 1:
            await asyncio.sleep(0.1)
            stats.add_inbound(random.randrange(100000))
            stats.add_outbound(random.randrange(100000))
            if random.random() < 0.1:
                logging.error("random error %d", random.randrange(100))

    async def main() -> None:
        asyncio.create_task(random_traffic())
        await stats.render_forever()

    asyncio.run(main())
