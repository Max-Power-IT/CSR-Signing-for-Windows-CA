param(
    [switch]$SyntaxCheck
)

Set-StrictMode -Version 2.0

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Quote-Argument {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return '""' }
    if ($Value.Length -eq 0) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    $escaped = $Value -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

function Invoke-Tool {
    param(
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$WorkingDirectory = (Get-Location).Path
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FileName
    $psi.Arguments = ($Arguments | ForEach-Object { Quote-Argument $_ }) -join ' '
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    [void]$process.Start()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    [pscustomobject]@{
        FileName = $FileName
        Arguments = $Arguments
        CommandLine = "$FileName $($psi.Arguments)"
        ExitCode = $process.ExitCode
        StdOut = $stdout
        StdErr = $stderr
        Combined = (($stdout, $stderr) -join [Environment]::NewLine).Trim()
    }
}

function Get-SafeBaseName {
    param([string]$Path)
    $name = [IO.Path]::GetFileNameWithoutExtension($Path)
    if ([string]::IsNullOrWhiteSpace($name)) { $name = 'request' }
    return ($name -replace '[^\w\.-]+', '_').Trim('_')
}

function Convert-ToPem {
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutputPath
    )
    if (Test-Path -LiteralPath $InputPath) {
        return Invoke-Tool -FileName 'certutil.exe' -Arguments @('-encode', $InputPath, $OutputPath) -WorkingDirectory ([IO.Path]::GetDirectoryName($OutputPath))
    }
    return $null
}

function Parse-CertutilDump {
    param([string]$Dump)

    $subject = ''
    $san = New-Object System.Collections.Generic.List[string]
    $template = ''

    foreach ($line in ($Dump -split "`r?`n")) {
        if (-not $subject -and $line -match '^\s*Subject:\s*(.+?)\s*$') {
            $subject = $Matches[1].Trim()
        }
        if ($line -match '^\s*(DNS Name|DNS):\s*(.+?)\s*$') {
            $san.Add("dns=$($Matches[2].Trim())")
        }
        if ($line -match '^\s*(IP Address|IPAddress):\s*(.+?)\s*$') {
            $san.Add("ipaddress=$($Matches[2].Trim())")
        }
        if ($line -match '^\s*(RFC822 Name|Email):\s*(.+?)\s*$') {
            $san.Add("email=$($Matches[2].Trim())")
        }
        if ($line -match 'Certificate Template Name.*=\s*(.+?)\s*$') {
            $template = $Matches[1].Trim()
        }
    }

    [pscustomobject]@{
        Subject = $subject
        SubjectAltNames = @($san)
        Template = $template
    }
}

function ConvertTo-TemplateName {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $text = $Value.Trim()

    # certutil -CATemplates can prefix lines with enrollment flag columns, for
    # example: "0 1 2 WebServer: Web Server -- Auto-Enroll: Access is denied."
    $text = $text -replace '^\s*(?:\d+\s+)+', ''

    if ($text -match '^([A-Za-z][A-Za-z0-9_.-]*)\s*:') {
        return $Matches[1]
    }
    if ($text -match '^([A-Za-z][A-Za-z0-9_.-]*)\s+-\s+') {
        return $Matches[1]
    }
    if ($text -match '^([A-Za-z][A-Za-z0-9_.-]*)\s+') {
        return $Matches[1]
    }
    if ($text -match '^([A-Za-z][A-Za-z0-9_.-]*)$') {
        return $Matches[1]
    }
    return $text
}

function Get-CaTemplates {
    param([string]$CaConfig)

    $args = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($CaConfig)) {
        $args.Add('-config')
        $args.Add($CaConfig.Trim())
    }
    $args.Add('-CATemplates')

    $result = Invoke-Tool -FileName 'certutil.exe' -Arguments ([string[]]@($args)) -WorkingDirectory $env:TEMP
    $templates = @()
    foreach ($raw in ($result.Combined -split "`r?`n")) {
        $line = $raw.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^(CertUtil|Config|Connecting|The command|Templates|Denied|Access is denied)') { continue }

        $lineForParse = $line -replace '^\s*(?:\d+\s+)+', ''
        $name = ''
        $display = $line
        if ($lineForParse -match '^([A-Za-z][A-Za-z0-9_.-]+)\s*:\s*(.+)$') {
            $name = $Matches[1].Trim()
            $displayText = ($Matches[2].Trim() -replace '\s+--\s+Auto-Enroll:.*$', '')
            $display = "$name - $displayText"
        } elseif ($lineForParse -match '^([A-Za-z][A-Za-z0-9_.-]+)\s+(.+)$') {
            $name = $Matches[1].Trim()
            $displayText = ($Matches[2].Trim() -replace '\s+--\s+Auto-Enroll:.*$', '')
            $display = "$name - $displayText"
        } elseif ($lineForParse -match '^[A-Za-z][A-Za-z0-9_.-]+$') {
            $name = $lineForParse
            $display = $name
        }

        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $templates += [pscustomobject]@{
                Name = $name
                Display = $display
                Raw = $line
            }
        }
    }

    [pscustomobject]@{
        Result = $result
        Templates = $templates
    }
}

function Show-TemplatePicker {
    param(
        [object[]]$Templates,
        [string]$CurrentTemplate
    )

    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = 'Choose CA Template'
    $dialog.Size = New-Object System.Drawing.Size(620, 470)
    $dialog.StartPosition = 'CenterParent'
    $dialog.MinimizeBox = $false
    $dialog.MaximizeBox = $false
    $dialog.Font = $font

    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'
    $layout.ColumnCount = 1
    $layout.RowCount = 3
    $layout.Padding = New-Object System.Windows.Forms.Padding(10)
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 28)))
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 42)))
    $dialog.Controls.Add($layout)

    $label = New-Object System.Windows.Forms.Label
    $label.Text = 'Select a certificate template enabled on the CA.'
    $label.Dock = 'Fill'
    $layout.Controls.Add($label, 0, 0)

    $list = New-Object System.Windows.Forms.ListBox
    $list.Dock = 'Fill'
    $displayToName = @{}
    foreach ($template in $Templates) {
        $display = [string]$template.Display
        $name = [string]$template.Name
        if ([string]::IsNullOrWhiteSpace($display)) { $display = $name }
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $displayToName[$display] = $name
        [void]$list.Items.Add($display)
        if ($template.Name -eq $CurrentTemplate) {
            $list.SelectedItem = $display
        }
    }
    if ($list.SelectedIndex -lt 0 -and $list.Items.Count -gt 0) {
        $list.SelectedIndex = 0
    }
    $layout.Controls.Add($list, 0, 1)

    $buttons = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttons.Dock = 'Fill'
    $buttons.FlowDirection = 'RightToLeft'
    $layout.Controls.Add($buttons, 0, 2)

    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'Use Template'
    $ok.Width = 110
    $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $buttons.Controls.Add($ok)

    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'
    $cancel.Width = 90
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $buttons.Controls.Add($cancel)

    $dialog.AcceptButton = $ok
    $dialog.CancelButton = $cancel
    $list.Add_DoubleClick({ $dialog.DialogResult = [System.Windows.Forms.DialogResult]::OK; $dialog.Close() })

    if ($dialog.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK -and $list.SelectedItem) {
        $selected = [string]$list.SelectedItem
        if ($displayToName.ContainsKey($selected)) {
            return $displayToName[$selected]
        }
        return $selected
    }
    return $null
}

function Select-CsrFile {
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = 'Certificate requests (*.csr;*.req;*.pem;*.der;*.txt)|*.csr;*.req;*.pem;*.der;*.txt|All files (*.*)|*.*'
    if (-not [string]::IsNullOrWhiteSpace($csrBox.Text)) {
        $existingDir = [IO.Path]::GetDirectoryName($csrBox.Text)
        if (-not [string]::IsNullOrWhiteSpace($existingDir) -and (Test-Path -LiteralPath $existingDir)) {
            $dlg.InitialDirectory = $existingDir
        }
    }
    if ($dlg.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
        $csrBox.Text = $dlg.FileName
        if ([string]::IsNullOrWhiteSpace($outBox.Text)) {
            $outBox.Text = [IO.Path]::GetDirectoryName($dlg.FileName)
        }
        return $true
    }
    return $false
}

function Build-AttributeString {
    param(
        [string]$Template,
        [string]$SanText,
        [string]$ExtraAttributes
    )

    $parts = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($Template)) {
        $templateName = ConvertTo-TemplateName $Template
        if (-not [string]::IsNullOrWhiteSpace($templateName)) {
            $parts.Add("CertificateTemplate:$templateName")
        }
    }

    $sanParts = New-Object System.Collections.Generic.List[string]
    foreach ($raw in ($SanText -split "`r?`n")) {
        $line = $raw.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^(dns|ip|ipaddress|email|upn|url)\s*[:=]\s*(.+)$') {
            $key = $Matches[1].ToLowerInvariant()
            if ($key -eq 'ip') { $key = 'ipaddress' }
            $sanParts.Add("$key=$($Matches[2].Trim())")
        } elseif ($line -match '^[a-zA-Z0-9.-]+$') {
            $sanParts.Add("dns=$line")
        } else {
            $sanParts.Add($line)
        }
    }
    if ($sanParts.Count -gt 0) {
        $parts.Add("SAN:$($sanParts -join '&')")
    }

    foreach ($raw in ($ExtraAttributes -split "`r?`n")) {
        $line = $raw.Trim()
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            $parts.Add($line)
        }
    }

    return ($parts -join "`n")
}

function Write-Metadata {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable]$Data
    )
    $Data | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Show-Message {
    param([string]$Text, [string]$Title = 'CSR CA Signer', [System.Windows.Forms.MessageBoxIcon]$Icon = [System.Windows.Forms.MessageBoxIcon]::Information)
    [void][System.Windows.Forms.MessageBox]::Show($Text, $Title, [System.Windows.Forms.MessageBoxButtons]::OK, $Icon)
}

function New-CertificateSignerIcon {
    $bitmap = New-Object System.Drawing.Bitmap 32, 32
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.Clear([System.Drawing.Color]::Transparent)

    $pageBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 252, 248, 232))
    $borderPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 72, 86, 106)), 1.6
    $linePen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 115, 128, 145)), 1
    $sealBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 193, 53, 53))
    $sealCenterBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 255, 226, 90))
    $signPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 24, 96, 170)), 2

    try {
        $graphics.FillRectangle($pageBrush, 5, 3, 20, 25)
        $graphics.DrawRectangle($borderPen, 5, 3, 20, 25)
        $graphics.DrawLine($linePen, 9, 9, 21, 9)
        $graphics.DrawLine($linePen, 9, 13, 21, 13)
        $graphics.DrawLine($linePen, 9, 17, 17, 17)

        $graphics.FillEllipse($sealBrush, 17, 18, 10, 10)
        $graphics.FillEllipse($sealCenterBrush, 20, 21, 4, 4)

        $graphics.DrawBezier($signPen, 7, 23, 11, 19, 13, 27, 17, 23)
        $graphics.DrawLine($signPen, 19, 26, 29, 14)
        $graphics.DrawLine($signPen, 25, 13, 30, 18)

        $handle = $bitmap.GetHicon()
        $icon = [System.Drawing.Icon]::FromHandle($handle).Clone()
        return $icon
    } finally {
        if ($graphics) { $graphics.Dispose() }
        foreach ($object in @($pageBrush, $borderPen, $linePen, $sealBrush, $sealCenterBrush, $signPen)) {
            if ($object) { $object.Dispose() }
        }
        if ($bitmap) { $bitmap.Dispose() }
    }
}

if ($SyntaxCheck) {
    'Syntax OK'
    return
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'CSR CA Signer'
$form.Icon = New-CertificateSignerIcon
$form.Size = New-Object System.Drawing.Size(1060, 820)
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = New-Object System.Drawing.Size(980, 740)

$font = New-Object System.Drawing.Font('Segoe UI', 9)
$form.Font = $font

$toolTip = New-Object System.Windows.Forms.ToolTip
$toolTip.AutoPopDelay = 12000
$toolTip.InitialDelay = 500
$toolTip.ReshowDelay = 200

$main = New-Object System.Windows.Forms.TableLayoutPanel
$main.Dock = 'Fill'
$main.ColumnCount = 1
$main.RowCount = 6
$main.Padding = New-Object System.Windows.Forms.Padding(10)
$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 152)))
$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 170)))
$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 128)))
$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 48)))
$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 28)))
$form.Controls.Add($main)

$filesGroup = New-Object System.Windows.Forms.GroupBox
$filesGroup.Text = 'Files and CA'
$filesGroup.Dock = 'Fill'
$filesGroup.Padding = New-Object System.Windows.Forms.Padding(8, 18, 8, 8)
$main.Controls.Add($filesGroup, 0, 0)

$files = New-Object System.Windows.Forms.TableLayoutPanel
$files.Dock = 'Fill'
$files.ColumnCount = 4
$files.RowCount = 3
$files.Padding = New-Object System.Windows.Forms.Padding(0, 2, 0, 0)
$files.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 92)))
$files.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$files.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 96)))
$files.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 122)))
$files.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 34)))
$files.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 34)))
$files.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 34)))
$filesGroup.Controls.Add($files)

$csrLabel = New-Object System.Windows.Forms.Label
$csrLabel.Text = 'CSR'
$csrLabel.TextAlign = 'MiddleLeft'
$files.Controls.Add($csrLabel, 0, 0)
$csrBox = New-Object System.Windows.Forms.TextBox
$csrBox.Dock = 'Fill'
$files.Controls.Add($csrBox, 1, 0)
$browseCsr = New-Object System.Windows.Forms.Button
$browseCsr.Text = 'Browse'
$files.Controls.Add($browseCsr, 2, 0)
$loadCsr = New-Object System.Windows.Forms.Button
$loadCsr.Text = 'Load CSR'
$files.Controls.Add($loadCsr, 3, 0)

$outLabel = New-Object System.Windows.Forms.Label
$outLabel.Text = 'Output'
$outLabel.TextAlign = 'MiddleLeft'
$files.Controls.Add($outLabel, 0, 1)
$outBox = New-Object System.Windows.Forms.TextBox
$outBox.Dock = 'Fill'
$files.Controls.Add($outBox, 1, 1)
$browseOut = New-Object System.Windows.Forms.Button
$browseOut.Text = 'Browse'
$files.Controls.Add($browseOut, 2, 1)

$caLabel = New-Object System.Windows.Forms.Label
$caLabel.Text = 'CA config'
$caLabel.TextAlign = 'MiddleLeft'
$files.Controls.Add($caLabel, 0, 2)
$caBox = New-Object System.Windows.Forms.TextBox
$caBox.Dock = 'Fill'
$files.Controls.Add($caBox, 1, 2)
$detectCa = New-Object System.Windows.Forms.Button
$detectCa.Text = 'Detect'
$files.Controls.Add($detectCa, 2, 2)

$fieldsGroup = New-Object System.Windows.Forms.GroupBox
$fieldsGroup.Text = 'Request Fields'
$fieldsGroup.Dock = 'Fill'
$main.Controls.Add($fieldsGroup, 0, 1)

$fields = New-Object System.Windows.Forms.TableLayoutPanel
$fields.Dock = 'Fill'
$fields.ColumnCount = 4
$fields.RowCount = 4
$fields.Padding = New-Object System.Windows.Forms.Padding(8, 6, 8, 6)
$fields.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 92)))
$fields.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
$fields.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 108)))
$fields.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
$fields.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 30)))
$fields.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 30)))
$fields.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$fields.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 20)))
$fieldsGroup.Controls.Add($fields)

$subjectLabel = New-Object System.Windows.Forms.Label
$subjectLabel.Text = 'CSR subject'
$subjectLabel.TextAlign = 'MiddleLeft'
$fields.Controls.Add($subjectLabel, 0, 0)
$subjectBox = New-Object System.Windows.Forms.TextBox
$subjectBox.Dock = 'Fill'
$subjectBox.ReadOnly = $true
$fields.Controls.Add($subjectBox, 1, 0)
$templateLabel = New-Object System.Windows.Forms.Label
$templateLabel.Text = 'Template'
$templateLabel.TextAlign = 'MiddleLeft'
$fields.Controls.Add($templateLabel, 2, 0)
$templateBox = New-Object System.Windows.Forms.TextBox
$templateBox.Dock = 'Fill'
$fields.Controls.Add($templateBox, 3, 0)

$requestIdLabel = New-Object System.Windows.Forms.Label
$requestIdLabel.Text = 'Request ID'
$requestIdLabel.TextAlign = 'MiddleLeft'
$fields.Controls.Add($requestIdLabel, 0, 1)
$requestIdBox = New-Object System.Windows.Forms.TextBox
$requestIdBox.Dock = 'Fill'
$fields.Controls.Add($requestIdBox, 1, 1)

$sanLabel = New-Object System.Windows.Forms.Label
$sanLabel.Text = 'SANs'
$sanLabel.TextAlign = 'TopLeft'
$fields.Controls.Add($sanLabel, 0, 2)
$sanBox = New-Object System.Windows.Forms.TextBox
$sanBox.Multiline = $true
$sanBox.ScrollBars = 'Vertical'
$sanBox.AcceptsReturn = $true
$sanBox.Dock = 'Fill'
$fields.Controls.Add($sanBox, 1, 2)

$attrLabel = New-Object System.Windows.Forms.Label
$attrLabel.Text = 'Extra attrs'
$attrLabel.TextAlign = 'TopLeft'
$fields.Controls.Add($attrLabel, 2, 2)
$attrBox = New-Object System.Windows.Forms.TextBox
$attrBox.Multiline = $true
$attrBox.ScrollBars = 'Vertical'
$attrBox.AcceptsReturn = $true
$attrBox.Dock = 'Fill'
$fields.Controls.Add($attrBox, 3, 2)

$note = New-Object System.Windows.Forms.Label
$note.Text = 'Subject/public key come from the CSR. Use template/SAN/extra attributes for CA policy fields.'
$note.Dock = 'Fill'
$fields.SetColumnSpan($note, 4)
$fields.Controls.Add($note, 0, 3)

$previewGroup = New-Object System.Windows.Forms.GroupBox
$previewGroup.Text = 'CSR Dump'
$previewGroup.Dock = 'Fill'
$main.Controls.Add($previewGroup, 0, 2)
$dumpBox = New-Object System.Windows.Forms.TextBox
$dumpBox.Multiline = $true
$dumpBox.ScrollBars = 'Both'
$dumpBox.WordWrap = $false
$dumpBox.ReadOnly = $true
$dumpBox.Dock = 'Fill'
$previewGroup.Controls.Add($dumpBox)

$actions = New-Object System.Windows.Forms.FlowLayoutPanel
$actions.Dock = 'Fill'
$actions.FlowDirection = 'LeftToRight'
$actions.WrapContents = $false
$main.Controls.Add($actions, 0, 3)

$submitButton = New-Object System.Windows.Forms.Button
$submitButton.Text = 'Submit and Sign'
$submitButton.Width = 130
$actions.Controls.Add($submitButton)

$retrieveButton = New-Object System.Windows.Forms.Button
$retrieveButton.Text = 'Retrieve Pending'
$retrieveButton.Width = 130
$actions.Controls.Add($retrieveButton)

$templatesButton = New-Object System.Windows.Forms.Button
$templatesButton.Text = 'CA Templates'
$templatesButton.Width = 118
$actions.Controls.Add($templatesButton)

$openOutButton = New-Object System.Windows.Forms.Button
$openOutButton.Text = 'Open Output'
$openOutButton.Width = 110
$actions.Controls.Add($openOutButton)

$clearButton = New-Object System.Windows.Forms.Button
$clearButton.Text = 'Clear Log'
$clearButton.Width = 90
$actions.Controls.Add($clearButton)

$logGroup = New-Object System.Windows.Forms.GroupBox
$logGroup.Text = 'Tool Output'
$logGroup.Dock = 'Fill'
$main.Controls.Add($logGroup, 0, 4)
$logBox = New-Object System.Windows.Forms.TextBox
$logBox.Multiline = $true
$logBox.ScrollBars = 'Both'
$logBox.WordWrap = $false
$logBox.ReadOnly = $true
$logBox.Dock = 'Fill'
$logGroup.Controls.Add($logBox)

$status = New-Object System.Windows.Forms.StatusStrip
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text = 'Ready'
$status.Items.Add($statusLabel) | Out-Null
$main.Controls.Add($status, 0, 5)

$toolTip.SetToolTip($caBox, 'Use ServerName\CAName. Leave blank to let certreq use the default picker/CA behavior.')
$toolTip.SetToolTip($templateBox, 'AD CS template short name, for example WebServer.')
$toolTip.SetToolTip($sanBox, 'One SAN per line. Examples: dns=www.example.com, ip=192.0.2.10, email=user@example.com, upn=user@example.com.')
$toolTip.SetToolTip($attrBox, 'One certreq attribute per line. These are appended to the -attrib string.')

function Append-Log {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return }
    $logBox.AppendText($Text.TrimEnd() + [Environment]::NewLine + [Environment]::NewLine)
}

function Set-Busy {
    param([bool]$Busy, [string]$Text)
    $form.Cursor = if ($Busy) { [System.Windows.Forms.Cursors]::WaitCursor } else { [System.Windows.Forms.Cursors]::Default }
    $submitButton.Enabled = -not $Busy
    $retrieveButton.Enabled = -not $Busy
    $templatesButton.Enabled = -not $Busy
    $loadCsr.Enabled = -not $Busy
    $statusLabel.Text = $Text
    [System.Windows.Forms.Application]::DoEvents()
}

function Get-OutputPrefix {
    param([string]$Action)
    $dir = $outBox.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($dir)) {
        if (-not [string]::IsNullOrWhiteSpace($csrBox.Text)) {
            $dir = [IO.Path]::GetDirectoryName($csrBox.Text)
        }
        if ([string]::IsNullOrWhiteSpace($dir)) {
            $dir = [Environment]::GetFolderPath('Desktop')
        }
        $outBox.Text = $dir
    }
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    $base = if (-not [string]::IsNullOrWhiteSpace($csrBox.Text)) { Get-SafeBaseName $csrBox.Text } else { "request-$Action" }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    Join-Path $dir "$base-$Action-$stamp"
}

function Complete-Outputs {
    param(
        [string]$Prefix,
        [object]$ToolResult,
        [string]$Action,
        [string]$RequestId
    )
    $certPath = "$Prefix.cer"
    $chainPath = "$Prefix.p7b"
    $responsePath = "$Prefix.rsp"
    $logPath = "$Prefix.log.txt"
    $detailsPath = "$Prefix.details.txt"
    $metadataPath = "$Prefix.metadata.json"

    $ToolResult.Combined | Set-Content -LiteralPath $logPath -Encoding UTF8
    Append-Log "Saved log: $logPath"

    $pemResult = Convert-ToPem -InputPath $certPath -OutputPath "$Prefix.pem"
    if ($pemResult) { Append-Log $pemResult.Combined }
    $chainPemResult = Convert-ToPem -InputPath $chainPath -OutputPath "$Prefix.chain.pem"
    if ($chainPemResult) { Append-Log $chainPemResult.Combined }

    if (Test-Path -LiteralPath $certPath) {
        $dump = Invoke-Tool -FileName 'certutil.exe' -Arguments @('-dump', $certPath) -WorkingDirectory ([IO.Path]::GetDirectoryName($certPath))
        $dump.Combined | Set-Content -LiteralPath $detailsPath -Encoding UTF8
        Append-Log "Saved certificate dump: $detailsPath"
    }

    Write-Metadata -Path $metadataPath -Data @{
        action = $Action
        csr = $csrBox.Text
        caConfig = $caBox.Text
        template = $templateBox.Text
        attributes = Build-AttributeString -Template $templateBox.Text -SanText $sanBox.Text -ExtraAttributes $attrBox.Text
        requestId = $RequestId
        created = (Get-Date).ToString('o')
        files = @{
            certificateDer = $certPath
            certificatePem = "$Prefix.pem"
            chainP7b = $chainPath
            chainPem = "$Prefix.chain.pem"
            fullResponse = $responsePath
            log = $logPath
            details = $detailsPath
            metadata = $metadataPath
        }
    }
    Append-Log "Saved metadata: $metadataPath"
}

$browseCsr.Add_Click({
    [void](Select-CsrFile)
})

$browseOut.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    if (-not [string]::IsNullOrWhiteSpace($outBox.Text) -and (Test-Path -LiteralPath $outBox.Text)) {
        $dlg.SelectedPath = $outBox.Text
    }
    if ($dlg.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
        $outBox.Text = $dlg.SelectedPath
    }
})

$loadCsr.Add_Click({
    try {
        if ([string]::IsNullOrWhiteSpace($csrBox.Text) -or -not (Test-Path -LiteralPath $csrBox.Text)) {
            if (-not (Select-CsrFile)) {
                $statusLabel.Text = 'CSR load cancelled'
                return
            }
            if ([string]::IsNullOrWhiteSpace($csrBox.Text) -or -not (Test-Path -LiteralPath $csrBox.Text)) {
                $statusLabel.Text = 'No CSR selected'
                return
            }
        }
        Set-Busy $true 'Loading CSR'
        $result = Invoke-Tool -FileName 'certutil.exe' -Arguments @('-dump', $csrBox.Text) -WorkingDirectory ([IO.Path]::GetDirectoryName($csrBox.Text))
        if ($result.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($result.Combined)) {
            $result = Invoke-Tool -FileName 'certreq.exe' -Arguments @('-dump', $csrBox.Text) -WorkingDirectory ([IO.Path]::GetDirectoryName($csrBox.Text))
        }
        $dumpBox.Text = $result.Combined
        Append-Log $result.CommandLine
        Append-Log $result.Combined

        $parsed = Parse-CertutilDump $result.Combined
        $subjectBox.Text = $parsed.Subject
        if ([string]::IsNullOrWhiteSpace($templateBox.Text) -and -not [string]::IsNullOrWhiteSpace($parsed.Template)) {
            $templateBox.Text = $parsed.Template
        }
        if ([string]::IsNullOrWhiteSpace($sanBox.Text) -and $parsed.SubjectAltNames.Count -gt 0) {
            $sanBox.Text = ($parsed.SubjectAltNames -join [Environment]::NewLine)
        }
        if ([string]::IsNullOrWhiteSpace($parsed.Subject)) {
            Append-Log 'CSR subject was not detected. Use a CA template that supplies the subject, or regenerate the CSR if the CA requires a subject in the request.'
        }
        if ($parsed.SubjectAltNames.Count -eq 0) {
            Append-Log 'No SAN entries were detected. Add SANs if the issued certificate needs DNS/IP names and the CA permits SAN attributes.'
        }
        $statusLabel.Text = 'CSR loaded'
    } catch {
        Show-Message $_.Exception.Message 'CSR load failed' ([System.Windows.Forms.MessageBoxIcon]::Error)
        Append-Log $_.Exception.ToString()
    } finally {
        Set-Busy $false $statusLabel.Text
    }
})

$templatesButton.Add_Click({
    try {
        Set-Busy $true 'Loading CA templates'
        $info = Get-CaTemplates -CaConfig $caBox.Text
        Append-Log $info.Result.CommandLine
        Append-Log $info.Result.Combined
        if ($info.Result.ExitCode -ne 0) {
            Show-Message "certutil exited with code $($info.Result.ExitCode). Review the tool output log." 'Template load failed' ([System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        if ($info.Templates.Count -eq 0) {
            Show-Message 'No templates were parsed from the CA output. Review the tool output log; you may need to enter CA config as Server\CAName first.' 'No templates found' ([System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        $choice = Show-TemplatePicker -Templates $info.Templates -CurrentTemplate $templateBox.Text
        if (-not [string]::IsNullOrWhiteSpace($choice)) {
            $choice = ConvertTo-TemplateName $choice
            $templateBox.Text = $choice
            $statusLabel.Text = "Template selected: $choice"
            Append-Log "Selected template short name: $choice"
        } else {
            $statusLabel.Text = 'Template selection cancelled'
        }
    } catch {
        Show-Message $_.Exception.Message 'Template load failed' ([System.Windows.Forms.MessageBoxIcon]::Error)
        Append-Log $_.Exception.ToString()
    } finally {
        Set-Busy $false $statusLabel.Text
    }
})

$detectCa.Add_Click({
    try {
        Set-Busy $true 'Detecting CA'
        $result = Invoke-Tool -FileName 'certutil.exe' -Arguments @('-config', '-', '-ping') -WorkingDirectory $env:TEMP
        Append-Log $result.CommandLine
        Append-Log $result.Combined
        if ($result.Combined -match 'Config(?:uration)?:\s*["'']?([^"'']+\\[^"'']+)["'']?') {
            $caBox.Text = $Matches[1].Trim()
        } elseif ($result.Combined -match '([A-Za-z0-9_.-]+\\[A-Za-z0-9_. -]+)') {
            $caBox.Text = $Matches[1].Trim()
        } else {
            Show-Message 'CA detection did not return a single config string. Copy the Server\CAName value from the log into CA config.' 'CA detection'
        }
    } catch {
        Show-Message $_.Exception.Message 'CA detection failed' ([System.Windows.Forms.MessageBoxIcon]::Error)
        Append-Log $_.Exception.ToString()
    } finally {
        Set-Busy $false 'Ready'
    }
})

$submitButton.Add_Click({
    try {
        if (-not (Test-Path -LiteralPath $csrBox.Text)) {
            Show-Message 'Choose an existing CSR file first.' 'CSR CA Signer' ([System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        Set-Busy $true 'Submitting CSR'
        $prefix = Get-OutputPrefix 'signed'
        $certPath = "$prefix.cer"
        $chainPath = "$prefix.p7b"
        $responsePath = "$prefix.rsp"
        $attrib = Build-AttributeString -Template $templateBox.Text -SanText $sanBox.Text -ExtraAttributes $attrBox.Text
        $args = New-Object System.Collections.Generic.List[string]
        $args.Add('-submit')
        $args.Add('-binary')
        if (-not [string]::IsNullOrWhiteSpace($caBox.Text)) {
            $args.Add('-config')
            $args.Add($caBox.Text.Trim())
        }
        if (-not [string]::IsNullOrWhiteSpace($attrib)) {
            $args.Add('-attrib')
            $args.Add($attrib)
        }
        $args.Add($csrBox.Text.Trim())
        $args.Add($certPath)
        $args.Add($chainPath)
        $args.Add($responsePath)

        $result = Invoke-Tool -FileName 'certreq.exe' -Arguments $args.ToArray() -WorkingDirectory ([IO.Path]::GetDirectoryName($certPath))
        Append-Log $result.CommandLine
        Append-Log $result.Combined

        $rid = ''
        if ($result.Combined -match '(?i)RequestId\s*[:=]\s*(\d+)') {
            $rid = $Matches[1]
            $requestIdBox.Text = $rid
        } elseif ($result.Combined -match '(?i)Request\s+ID\s*[:=]?\s*(\d+)') {
            $rid = $Matches[1]
            $requestIdBox.Text = $rid
        }

        Complete-Outputs -Prefix $prefix -ToolResult $result -Action 'submit' -RequestId $rid
        if ((Test-Path -LiteralPath $certPath) -and $result.ExitCode -eq 0) {
            Show-Message "Certificate issued.`n`n$certPath" 'Certificate issued'
        } elseif ($rid) {
            Show-Message "Request is pending or needs CA approval. Request ID: $rid" 'Request submitted' ([System.Windows.Forms.MessageBoxIcon]::Warning)
        } else {
            Show-Message "certreq exited with code $($result.ExitCode). Review the tool output log." 'Submit finished' ([System.Windows.Forms.MessageBoxIcon]::Warning)
        }
        $statusLabel.Text = 'Submit finished'
    } catch {
        Show-Message $_.Exception.Message 'Submit failed' ([System.Windows.Forms.MessageBoxIcon]::Error)
        Append-Log $_.Exception.ToString()
    } finally {
        Set-Busy $false $statusLabel.Text
    }
})

$retrieveButton.Add_Click({
    try {
        $rid = $requestIdBox.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($rid) -or $rid -notmatch '^\d+$') {
            Show-Message 'Enter a numeric pending Request ID first.' 'CSR CA Signer' ([System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        Set-Busy $true 'Retrieving request'
        $prefix = Get-OutputPrefix "request-$rid"
        $certPath = "$prefix.cer"
        $chainPath = "$prefix.p7b"
        $responsePath = "$prefix.rsp"
        $args = New-Object System.Collections.Generic.List[string]
        $args.Add('-retrieve')
        $args.Add('-binary')
        if (-not [string]::IsNullOrWhiteSpace($caBox.Text)) {
            $args.Add('-config')
            $args.Add($caBox.Text.Trim())
        }
        $args.Add($rid)
        $args.Add($certPath)
        $args.Add($chainPath)
        $args.Add($responsePath)

        $result = Invoke-Tool -FileName 'certreq.exe' -Arguments $args.ToArray() -WorkingDirectory ([IO.Path]::GetDirectoryName($certPath))
        Append-Log $result.CommandLine
        Append-Log $result.Combined
        Complete-Outputs -Prefix $prefix -ToolResult $result -Action 'retrieve' -RequestId $rid
        if ((Test-Path -LiteralPath $certPath) -and $result.ExitCode -eq 0) {
            Show-Message "Certificate retrieved.`n`n$certPath" 'Certificate retrieved'
        } else {
            Show-Message "Retrieve exited with code $($result.ExitCode). Review the tool output log." 'Retrieve finished' ([System.Windows.Forms.MessageBoxIcon]::Warning)
        }
        $statusLabel.Text = 'Retrieve finished'
    } catch {
        Show-Message $_.Exception.Message 'Retrieve failed' ([System.Windows.Forms.MessageBoxIcon]::Error)
        Append-Log $_.Exception.ToString()
    } finally {
        Set-Busy $false $statusLabel.Text
    }
})

$openOutButton.Add_Click({
    $dir = $outBox.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($dir) -or -not (Test-Path -LiteralPath $dir)) {
        Show-Message 'Output folder does not exist yet.' 'CSR CA Signer' ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    Start-Process explorer.exe -ArgumentList $dir
})

$clearButton.Add_Click({
    $logBox.Clear()
})

$form.Add_Shown({
    $statusLabel.Text = 'Ready'
})

[void][System.Windows.Forms.Application]::EnableVisualStyles()
[void][System.Windows.Forms.Application]::Run($form)
