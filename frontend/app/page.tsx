"use client";

import AttackLab from "@/src/screens/AttackLab";
import CommandCenter from "@/src/screens/CommandCenter";
import Debrief from "@/src/screens/Debrief";
import InitializeRange from "@/src/screens/InitializeRange";
import Landing from "@/src/screens/Landing";
import ModeSelect from "@/src/screens/ModeSelect";
import { SessionProvider, useSession } from "@/src/state/session";

function Stage() {
  const { stage } = useSession();
  switch (stage) {
    case "LANDING":
      return <Landing />;
    case "INITIALIZE":
      return <InitializeRange />;
    case "MODE_SELECT":
      return <ModeSelect />;
    case "ATTACK_LAB":
      return <AttackLab />;
    case "COMMAND_CENTER":
      return <CommandCenter />;
    case "DEBRIEF":
      return <Debrief />;
  }
}

export default function Console() {
  return (
    <SessionProvider>
      <Stage />
    </SessionProvider>
  );
}
