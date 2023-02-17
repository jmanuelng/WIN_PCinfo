# WIN_PCinfo

<p>Script I use to perform a Windows device review as one of the first steps on Microsoft Intune projects. It's a basic scrpt to extract basic and complete computer information using various Windows Management Instrumentation (WMI) classes and the "systeminfo" command. Additionally, the script retrieves license, activation information using Software Licensing Management Tool, network device info and more.</p>
<p>It collects a comprehensive set of information from a device, allows understanding of current environment and helps identify potential issues that might cause problems during a Microso Intune project, this based on my experiencia. The script will gather:</p>
<ul>
  <li><strong>Computer information:</strong> The device's name, owner, domain, memory, manufacturer, and model, some detailed configuration information about OS, including system configuration, security information, product ID, and hardware properties.</li>
  <li><strong>Software Licensing Management Tool information:</strong> License and activation information for the installed active Windows.</li>    
  <li><strong>Software Inventory:</strong> Gets Software inventory information using CimInstance and from registry uninstall details. (in future will add WinGet list).</li>
  <li><strong>Network Adapter: Detail on network adapter información and WiFi Profiles.</li>
  <li><strong>Battery report:</strong>The Battery "Powercfg /batteryreport" report.</li>
</ul>
<p>Script creates output files and organized by folders.</p>
