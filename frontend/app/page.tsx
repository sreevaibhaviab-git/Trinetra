import AgentExecution from "@/src/components/AgentExecution";
import CommandBar from "@/src/components/CommandBar";
import CommanderConsole from "@/src/components/CommanderConsole";
import IncidentIntelligence from "@/src/components/IncidentIntelligence";
import InfrastructureGraph from "@/src/components/InfrastructureGraph";

export default function Console() {
  return (
    <main className="flex h-screen flex-col overflow-hidden">
      <CommandBar />
      <div className="grid min-h-0 flex-1 grid-cols-[27fr_48fr_25fr] divide-x divide-line">
        <CommanderConsole />
        <InfrastructureGraph />
        <IncidentIntelligence />
      </div>
      <AgentExecution />
    </main>
  );
}
