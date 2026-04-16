export default function Guide() {
  return (
    <div className="max-w-4xl space-y-10 text-gray-700">
      <div>
        <div className="flex items-center gap-3">
          <h2 className="text-2xl font-bold text-gray-800">Guide</h2>
        </div>
        <p className="mt-1 text-sm text-gray-500">
          Todo lo que necesitas saber para entender y usar ThreatScope.
        </p>
      </div>

      {/* Como usar */}
      <section className="rounded-xl border border-blue-100 bg-blue-50 p-6 shadow-sm space-y-3">
        <h3 className="text-lg font-semibold text-blue-800">Quick Start — Como usar la herramienta</h3>
        <ol className="list-decimal list-inside space-y-2 text-sm text-blue-900">
          <li>
            <strong>Consigue un archivo .evtx</strong> — exporta desde el Visor de Eventos de
            Windows (<code className="rounded bg-blue-100 px-1">eventvwr.msc</code>) o usa un log
            de practica de plataformas como BOTS de Splunk, Blue Team Labs o CyberDefenders.
          </li>
          <li>
            <strong>Sube el archivo</strong> en la seccion <em>Upload</em>. El backend lo parsea,
            evalua las reglas y guarda los resultados en la base de datos.
          </li>
          <li>
            <strong>Revisa el Dashboard</strong> para ver el resumen de eventos y alertas por
            severidad.
          </li>
          <li>
            <strong>Investiga las Alertas</strong> — filtra por severidad, lee la descripcion y
            consulta la tecnica MITRE para entender el contexto del ataque.
          </li>
          <li>
            <strong>Explora los Eventos</strong> raw en la seccion Events para ver los registros
            originales parseados.
          </li>
        </ol>
      </section>

      {/* Que es un SIEM */}
      <section className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm space-y-3">
        <h3 className="text-lg font-semibold text-gray-800">Que es un SIEM?</h3>
        <p>
          Un <strong>SIEM (Security Information and Event Management)</strong> es una herramienta
          que recopila, centraliza y analiza eventos de seguridad provenientes de distintas fuentes
          de un sistema informatico. Su objetivo es detectar actividad sospechosa o maliciosa en
          tiempo real correlacionando multiples señales.
        </p>
        <p>
          Los SIEMs profesionales (Splunk, Microsoft Sentinel, IBM QRadar) procesan millones de
          eventos por segundo. <strong>ThreatScope</strong> es una version didactica que aplica los
          mismos principios a escala reducida para que puedas aprender como funciona por dentro.
        </p>
      </section>

      {/* Flujo de datos */}
      <section className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm space-y-4">
        <h3 className="text-lg font-semibold text-gray-800">Flujo de datos</h3>
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3 text-sm font-medium">
          {[
            { step: "1", label: "Archivo .evtx", desc: "Log de Windows" },
            { step: "2", label: "Parser", desc: "Extrae campos del XML" },
            { step: "3", label: "Reglas", desc: "Evalua cada evento" },
            { step: "4", label: "Correlacion", desc: "Detecta patrones multi-evento" },
            { step: "5", label: "Alertas", desc: "Resultado visible en el dashboard" },
          ].map((item, i, arr) => (
            <div key={item.step} className="flex items-center gap-3">
              <div className="flex flex-col items-center">
                <div className="flex h-9 w-9 items-center justify-center rounded-full bg-blue-600 text-white text-sm font-bold">
                  {item.step}
                </div>
                <span className="mt-1 text-xs font-semibold text-gray-800">{item.label}</span>
                <span className="text-xs text-gray-400">{item.desc}</span>
              </div>
              {i < arr.length - 1 && (
                <span className="text-gray-300 text-xl mb-4">→</span>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* Fuentes de logs soportadas */}
      <section className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm space-y-3">
        <h3 className="text-lg font-semibold text-gray-800">Fuentes de logs soportadas</h3>
        <p className="text-sm">
          ThreatScope acepta cualquier archivo <code className="rounded bg-gray-100 px-1">.evtx</code> de
          Windows. Las reglas de deteccion cubren estas fuentes:
        </p>
        <div className="overflow-hidden rounded-lg border border-gray-200 text-sm">
          <table className="w-full">
            <thead className="bg-gray-50 text-xs uppercase text-gray-500">
              <tr>
                <th className="px-4 py-2 text-left">Fuente</th>
                <th className="px-4 py-2 text-left">Canal (.evtx)</th>
                <th className="px-4 py-2 text-left">Que monitoriza</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {[
                ["Sysmon", "Microsoft-Windows-Sysmon/Operational", "Procesos, red, inyeccion, ADS, acceso a LSASS"],
                ["Windows Security", "Security", "Logons, creacion de usuarios, privilegios, tareas programadas"],
                ["PowerShell", "Microsoft-Windows-PowerShell/Operational", "Script blocks, descargas, obfuscacion"],
              ].map(([src, canal, desc]) => (
                <tr key={src} className="hover:bg-gray-50">
                  <td className="px-4 py-2 font-medium text-gray-800">{src}</td>
                  <td className="px-4 py-2 text-xs text-gray-500 font-mono">{canal}</td>
                  <td className="px-4 py-2 text-gray-600">{desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Reglas de deteccion */}
      <section className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm space-y-3">
        <h3 className="text-lg font-semibold text-gray-800">Reglas de deteccion</h3>
        <p className="text-sm">
          Cada evento ingresado se evalua contra todas las reglas. Una regla genera una alerta
          cuando el evento cumple sus condiciones. Cada regla esta mapeada al framework{" "}
          <strong>MITRE ATT&CK</strong>.
        </p>
        <div className="overflow-hidden rounded-lg border border-gray-200 text-sm">
          <table className="w-full">
            <thead className="bg-gray-50 text-xs uppercase text-gray-500">
              <tr>
                <th className="px-4 py-2 text-left">Regla</th>
                <th className="px-4 py-2 text-left">Severidad</th>
                <th className="px-4 py-2 text-left">Tactica MITRE</th>
                <th className="px-4 py-2 text-left">Tecnica</th>
                <th className="px-4 py-2 text-left">Fuente</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {[
                ["PowerShell obfuscado (Proc)", "High", "Execution", "T1059.001", "Sysmon"],
                ["Acceso a LSASS", "Critical", "Credential Access", "T1003.001", "Sysmon"],
                ["Remote Thread Injection", "High", "Defense Evasion", "T1055.003", "Sysmon"],
                ["Conexion de red sospechosa", "Medium", "Command & Control", "T1071", "Sysmon"],
                ["Alternate Data Stream", "Medium", "Defense Evasion", "T1564.004", "Sysmon"],
                ["Logon fallido", "Medium", "Credential Access", "T1110", "Security"],
                ["Credenciales explicitas (4648)", "High", "Lateral Movement", "T1550.002", "Security"],
                ["Privilegios sensibles asignados", "High", "Privilege Escalation", "T1134", "Security"],
                ["Nueva cuenta de usuario", "High", "Persistence", "T1136.001", "Security"],
                ["Tarea programada creada", "Medium", "Persistence", "T1053.005", "Security"],
                ["Script block sospechoso (4104)", "High", "Execution", "T1059.001", "PowerShell"],
                ["Descarga con PowerShell (4103)", "High", "Command & Control", "T1105", "PowerShell"],
              ].map(([rule, sev, tactic, tech, src]) => (
                <tr key={rule} className="hover:bg-gray-50">
                  <td className="px-4 py-2 font-medium text-gray-800">{rule}</td>
                  <td className="px-4 py-2">
                    <span className={`rounded px-2 py-0.5 text-xs font-semibold ${
                      sev === "Critical" ? "bg-red-100 text-red-700"
                      : sev === "High" ? "bg-orange-100 text-orange-700"
                      : "bg-yellow-100 text-yellow-700"
                    }`}>{sev}</span>
                  </td>
                  <td className="px-4 py-2 text-gray-600">{tactic}</td>
                  <td className="px-4 py-2 text-xs font-mono text-gray-500">{tech}</td>
                  <td className="px-4 py-2 text-xs text-gray-400">{src}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Correlaciones */}
      <section className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm space-y-3">
        <h3 className="text-lg font-semibold text-gray-800">Correlacion de eventos</h3>
        <p className="text-sm">
          La correlacion detecta <strong>patrones de ataque multi-paso</strong>: una sola accion
          puede no ser sospechosa, pero la combinacion de varias en una ventana de tiempo corta si
          lo es. ThreatScope evalua las correlaciones tras cada ingestion de archivo.
        </p>
        <div className="space-y-3 text-sm">
          {[
            {
              name: "Reconocimiento seguido de ejecucion",
              window: "5 min",
              steps: ["DNS query (Sysmon ID 22)", "PowerShell spawn (Sysmon ID 1)"],
              severity: "High",
              why: "Un atacante consulta un dominio C2 y luego lanza PowerShell para contactarlo.",
            },
            {
              name: "Movimiento lateral",
              window: "5 min",
              steps: ["Conexion de red (Sysmon ID 3)", "CreateRemoteThread (Sysmon ID 8)"],
              severity: "Critical",
              why: "Conexion saliente seguida de inyeccion de codigo en otro proceso.",
            },
            {
              name: "Ataque de fuerza bruta",
              window: "5 min",
              steps: ["5 o mas logons fallidos (Security ID 4625)"],
              severity: "Critical",
              why: "Multiples intentos fallidos en poco tiempo indican automatizacion.",
            },
            {
              name: "Escalada de privilegios tras fallo",
              window: "5 min",
              steps: ["Logon fallido (Security ID 4625)", "Privilegios sensibles asignados (Security ID 4672)"],
              severity: "Critical",
              why: "Un intento fallido seguido de una escalada exitosa sugiere exploit.",
            },
          ].map((c) => (
            <div key={c.name} className="rounded-lg border border-gray-100 bg-gray-50 p-4">
              <div className="flex items-start justify-between gap-2">
                <p className="font-semibold text-gray-800">{c.name}</p>
                <span className={`shrink-0 rounded px-2 py-0.5 text-xs font-semibold ${
                  c.severity === "Critical" ? "bg-red-100 text-red-700" : "bg-orange-100 text-orange-700"
                }`}>{c.severity}</span>
              </div>
              <p className="mt-1 text-xs text-gray-500">Ventana de tiempo: {c.window}</p>
              <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                {c.steps.map((s, i) => (
                  <span key={i} className="flex items-center gap-1">
                    <span className="rounded bg-blue-100 px-2 py-0.5 text-blue-700">{s}</span>
                    {i < c.steps.length - 1 && <span className="text-gray-400">→</span>}
                  </span>
                ))}
              </div>
              <p className="mt-2 text-xs text-gray-500 italic">{c.why}</p>
            </div>
          ))}
        </div>
      </section>

      {/* MITRE ATT&CK */}
      <section className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm space-y-3">
        <h3 className="text-lg font-semibold text-gray-800">Que es MITRE ATT&CK?</h3>
        <p className="text-sm">
          <strong>MITRE ATT&CK</strong> es una base de conocimiento publica que cataloga las
          tacticas, tecnicas y procedimientos (TTPs) que usan los atacantes reales. Cada tecnica
          tiene un ID unico (ej. <code className="rounded bg-gray-100 px-1">T1059.001</code>) que
          permite a los equipos de seguridad hablar un lenguaje comun y mapear detecciones a
          comportamientos conocidos.
        </p>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs text-center">
          {[
            { tactic: "Execution", color: "bg-purple-100 text-purple-700" },
            { tactic: "Persistence", color: "bg-green-100 text-green-700" },
            { tactic: "Privilege Escalation", color: "bg-orange-100 text-orange-700" },
            { tactic: "Credential Access", color: "bg-red-100 text-red-700" },
            { tactic: "Defense Evasion", color: "bg-blue-100 text-blue-700" },
            { tactic: "Lateral Movement", color: "bg-yellow-100 text-yellow-700" },
            { tactic: "Command & Control", color: "bg-pink-100 text-pink-700" },
            { tactic: "Exfiltration", color: "bg-gray-100 text-gray-600" },
          ].map((t) => (
            <span key={t.tactic} className={`rounded-lg px-3 py-2 font-medium ${t.color}`}>
              {t.tactic}
            </span>
          ))}
        </div>
      </section>

    </div>
  );
}
