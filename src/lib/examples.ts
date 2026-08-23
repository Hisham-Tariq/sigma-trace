/**
 * Worked examples. Every rule here is real SigmaHQ content and every event is a
 * real event from the public Nextron Windows baselines, so nothing on the page
 * is invented. The first example is the one this tool was built for.
 */
export interface Example {
  id: string;
  label: string;
  note: string;
  rule: string;
  event: string;
}

const RENAMED_BINARY_BASE = `title: Potential Defense Evasion Via Binary Rename
id: 36480ae1-a1cb-4eaa-a0d6-29801d7e9142
status: test
description: Detects the execution of a renamed binary, using the Sysmon OriginalFileName field.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName:
            - 'Cmd.Exe'
            - 'CONHOST.EXE'
            - '7z.exe'
            - 'WinRAR.exe'
            - 'wevtutil.exe'
            - 'net.exe'
            - 'netsh.exe'
            - 'InstallUtil.exe'
    filter:
        Image|endswith:
            - '\\cmd.exe'
            - '\\conhost.exe'
            - '\\7z.exe'
            - '\\WinRAR.exe'
            - '\\wevtutil.exe'
            - '\\net.exe'
            - '\\netsh.exe'
            - '\\InstallUtil.exe'
`;

const NINITE_EVENT = `UtcTime: 2022-02-08 11:46:04.808
ProcessId: 6068
Image: C:\\Users\\user\\AppData\\Local\\Temp\\46F399~1\\target.exe
FileVersion: 6.10.0
Description: WinRAR archiver
Product: WinRAR
Company: Alexander Roshal
OriginalFileName: WinRAR.exe
CommandLine: "C:\\Users\\user\\AppData\\Local\\Temp\\46F399~1\\target.exe" /S
User: DESKTOP-A8CALR3\\user
IntegrityLevel: High
ParentImage: C:\\Users\\user\\AppData\\Local\\Temp\\0cb1bbbb-88d4-11ec-89b1-080027dfe1cd\\Ninite.exe
ParentUser: DESKTOP-A8CALR3\\user
EventID: 1`;

const NINITE_FILTER = `    filter_optional_ninite:
        OriginalFileName: 'WinRAR.exe'
        Image|endswith: '\\target.exe'
        ParentImage|endswith: '\\Ninite.exe'
`;

export const EXAMPLES: Example[] = [
  {
    id: 'fp',
    label: 'False positive — Ninite installing WinRAR',
    note: 'A real rule firing on a clean Windows machine. Nothing here is an attack.',
    rule: RENAMED_BINARY_BASE + '    condition: selection and not filter\nlevel: medium\n',
    event: NINITE_EVENT,
  },
  {
    id: 'fixed',
    label: 'The fix — filter added and wired up',
    note: 'Same rule with a narrow filter, and the condition updated to use it. Now silent.',
    rule: RENAMED_BINARY_BASE + NINITE_FILTER +
      '    condition: selection and not filter and not 1 of filter_optional_*\nlevel: medium\n',
    event: NINITE_EVENT,
  },
  {
    id: 'dead',
    label: 'The trap — a filter the condition never uses',
    note: 'Valid YAML. Passes every linter. Does absolutely nothing, because the condition ignores it.',
    rule: RENAMED_BINARY_BASE + NINITE_FILTER + '    condition: selection and not filter\nlevel: medium\n',
    event: NINITE_EVENT,
  },
  {
    id: 'attack',
    label: 'A real renamed binary — the rule doing its job',
    note: "The rule's own regression sample: netsh renamed to hide it. The filter must not silence this.",
    rule: RENAMED_BINARY_BASE + NINITE_FILTER +
      '    condition: selection and not filter and not 1 of filter_optional_*\nlevel: medium\n',
    event: `Image: C:\\Users\\Administrator\\Downloads\\testdata\\renamed-netsh.exe
OriginalFileName: netsh.exe
ParentImage: C:\\Windows\\System32\\cmd.exe
CommandLine: renamed-netsh.exe
Product: Microsoft Windows Operating System
Company: Microsoft Corporation
EventID: 1`,
  },
  {
    id: 'quant',
    label: 'Quantifiers — "all of" and "1 of"',
    note: 'How 1 of x*, all of x* and them actually count. Change the numbers and watch the tree.',
    rule: `title: Suspicious PowerShell Encoded Command
id: 00000000-0000-0000-0000-000000000000
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    selection_enc:
        CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
    selection_hidden:
        CommandLine|contains: ' -w hidden'
    filter_main_sccm:
        ParentImage|startswith: 'C:\\Windows\\CCM\\'
    condition: all of selection_* and not 1 of filter_main_*
level: high
`,
    event: `Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
OriginalFileName: PowerShell.EXE
CommandLine: powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA
ParentImage: C:\\Windows\\System32\\cmd.exe
User: CORP\\jdoe
EventID: 1`,
  },
];

export const DEFAULT_EXAMPLE = EXAMPLES[0];
