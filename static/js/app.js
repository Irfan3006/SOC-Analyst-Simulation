document.addEventListener('DOMContentLoaded', () => {
    const themeToggleBtn = document.getElementById('themeToggleBtn');
    const themeIcon = document.getElementById('themeIcon');
    const body = document.body;

    let currentTheme = 'dark';

    if (localStorage.getItem('theme')) {
        currentTheme = localStorage.getItem('theme');
        if (currentTheme === 'light') {
            body.setAttribute('data-theme', 'light');
            body.classList.remove('dark-mode');
            themeIcon.classList.replace('fa-sun', 'fa-moon');
        }
    }

    themeToggleBtn.addEventListener('click', () => {
        if (body.getAttribute('data-theme') === 'light') {
            body.removeAttribute('data-theme');
            body.classList.add('dark-mode');
            themeIcon.classList.replace('fa-moon', 'fa-sun');
            localStorage.setItem('theme', 'dark');
        } else {
            body.setAttribute('data-theme', 'light');
            body.classList.remove('dark-mode');
            themeIcon.classList.replace('fa-sun', 'fa-moon');
            localStorage.setItem('theme', 'light');
        }
    });

    const liveLogTable = document.getElementById('live-log-table');
    const btnSimulate = document.getElementById('btn-simulate');

    const updateStats = (stats) => {
        document.getElementById('stat-total-logs').innerText = stats.total_logs;
        document.getElementById('stat-real-threats').innerText = stats.threats_detected;
        document.getElementById('stat-auto-reports').innerText = stats.reports_generated;
        if (document.getElementById('stat-manual-reports')) {
            document.getElementById('stat-manual-reports').innerText = stats.manual_reports;
        }
    };

    const fetchLogs = async () => {
        try {
            const res = await fetch('/api/logs');
            const logs = await res.json();
            logs.forEach(log => {
                if (!logIds.has(log.id)) {
                    logIds.add(log.id);
                    renderLog(log);
                }
            });
        } catch (err) {
            console.error(err);
        }
    };

    const fetchReports = async () => {
        try {
            const res = await fetch('/api/reports');
            const reports = await res.json();
            reports.forEach(report => {
                if (!reportedIds.has(report.id)) {
                    reportedIds.add(report.id);
                }
            });
        } catch (err) {
            console.error(err);
        }
    };

    const fetchStats = async () => {
        try {
            const res = await fetch('/api/stats');
            const stats = await res.json();
            updateStats(stats);
        } catch (err) {
            console.error(err);
        }
    };

    let reportedIds = new Set();
    let logIds = new Set();
    let currentLogIdForReport = null;

    const formatSeverity = (sev) => {
        const classes = {
            'Critical': 'badge-critical',
            'High': 'badge-high',
            'Medium': 'badge-medium',
            'Low': 'badge-low'
        };
        const iconClasses = {
            'Critical': 'fa-skull-crossbones',
            'High': 'fa-fire',
            'Medium': 'fa-exclamation-triangle',
            'Low': 'fa-info-circle'
        };
        return `<span class="badge ${classes[sev]}"><i class="fa-solid ${iconClasses[sev]} me-1"></i>${sev}</span>`;
    };

    const formatThreatType = (type) => {
        let icon = 'fa-bug';
        if (type === 'DDoS') icon = 'fa-network-wired';
        if (type === 'Brute Force') icon = 'fa-key';
        if (type === 'Malware Activity') icon = 'fa-spider';
        return `<i class="fa-solid ${icon} me-2"></i><strong>${type}</strong>`;
    };

    const renderLog = (log) => {
        const row = document.createElement('tr');
        row.style.animation = "pulse 2s 1 font-weight-bold";

        let statusHtml = log.is_false_positive ? `<span class="badge badge-fp"><i class="fa-solid fa-filter me-1"></i>False Positive</span>` : formatSeverity(log.severity);
        const confidenceClass = log.confidence_score > 85 ? 'text-danger fw-bold' : (log.confidence_score > 50 ? 'text-warning' : 'text-primary');

        let rowBgClass = log.is_false_positive ? 'TableRow-FP' : (log.severity === 'Critical' ? 'TableRow-Critical' : (log.severity === 'High' ? 'TableRow-High' : (log.severity === 'Medium' ? 'TableRow-Medium' : 'TableRow-Low')));
        let typeColorClass = log.is_false_positive ? 'text-fp' : (log.severity === 'Critical' ? 'text-critical' : (log.severity === 'High' ? 'text-high' : (log.severity === 'Medium' ? 'text-medium' : 'text-low')));

        row.className = rowBgClass;

        let actionBtn = (log.severity === 'Critical' || log.severity === 'High' || log.severity === 'Medium') ? `<button class="btn btn-sm btn-outline-primary py-0" onclick="window.openReportModal(${log.id})"><i class="fa-solid fa-file-pdf"></i> Gen</button>` : `<span class="text-muted small"><i class="fa-solid fa-minus"></i></span>`;

        row.innerHTML = `
            <td class="text-muted small border-0">${log.timestamp.split(' ')[1]}</td>
            <td class="${typeColorClass} border-0">${formatThreatType(log.type)}</td>
            <td class="font-monospace small border-0">
                <strong class="text-primary fs-6">${log.source}</strong> 
                <div class="text-muted d-none d-sm-block" style="font-size:0.75rem">
                    <i class="fa-solid fa-crosshairs me-1"></i>${log.target}
                </div>
            </td>
            <td class="border-0"><span class="${confidenceClass}">${log.confidence_score}%</span></td>
            <td class="border-0">${statusHtml}</td>
            <td class="border-0 text-center">${actionBtn}</td>
        `;

        if (liveLogTable.firstChild) liveLogTable.insertBefore(row, liveLogTable.firstChild);
        else liveLogTable.appendChild(row);

        while (liveLogTable.children.length > 50) liveLogTable.removeChild(liveLogTable.lastChild);
    };

    btnSimulate.addEventListener('click', async () => {
        try {
            const originalIcon = btnSimulate.innerHTML;
            btnSimulate.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-1"></i> Generating...';
            btnSimulate.disabled = true;

            const res = await fetch('/api/generate_log', { method: 'POST' });
            const data = await res.json();

            updateStats(data.stats);
            if (!logIds.has(data.log.id)) {
                logIds.add(data.log.id);
                renderLog(data.log);
            }

            setTimeout(() => {
                btnSimulate.innerHTML = originalIcon;
                btnSimulate.disabled = false;
            }, 500);
        } catch (err) {
            console.error(err);
            btnSimulate.innerHTML = '<i class="fa-solid fa-bolt me-1"></i> Trigger Simulasi';
            btnSimulate.disabled = false;
        }
    });

    const reportModal = new bootstrap.Modal(document.getElementById('reportModal'));
    const modalIncidentId = document.getElementById('modalIncidentId');
    const selectionView = document.getElementById('reportSelectionView');
    const resultView = document.getElementById('reportResultView');
    const manualView = document.getElementById('manualReportView');
    const manualEditor = document.getElementById('manualReportEditor');
    const loadingView = document.getElementById('reportLoadingView');
    const modalFooter = document.getElementById('reportModalFooter');
    const pdfContentArea = document.getElementById('pdfContentArea');
    const pdfPrintableArea = document.getElementById('pdfPrintableArea');

    window.openReportModal = (logId) => {
        currentLogIdForReport = logId;
        modalIncidentId.innerText = `#${logId}`;
        selectionView.style.display = 'block';
        manualView.style.display = 'none';
        loadingView.style.display = 'none';
        resultView.style.display = 'none';
        modalFooter.style.display = 'none';
        reportModal.show();
    };

    const getManualTemplate = (log) => {
        return `Laporan Keamanan Manual\nID Insiden: #${log.id}\nWaktu: ${log.timestamp}\n\nRingkasan Insiden\n- Tipe Serangan: ${log.type}\n- Target System: ${log.target}\n- Source IP: ${log.source}\n- Severity: ${log.severity}\n- Confidence Score: ${log.confidence_score}%\n\nAnalisis Teknikal\n...\n\nLangkah Mitigasi\n-\n-\n-\n\nKesimpulan\n...\n`;
    };

    const processReport = async (type, manualContent = null) => {
        document.getElementById('btnGenStandard').disabled = true;
        document.getElementById('btnGenManual').disabled = true;
        if (type === 'standard') loadingView.style.display = 'block';

        try {
            const res = await fetch('/api/generate_ondemand_report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ log_id: currentLogIdForReport, type, manual_content: manualContent })
            });
            const data = await res.json();

            if (data.status === 'success') {
                updateStats(data.stats);
                pdfContentArea.innerHTML = marked.parse(data.report.content);
                if (!reportedIds.has(data.report.id)) reportedIds.add(data.report.id);
                selectionView.style.display = 'none';
                manualView.style.display = 'none';
                resultView.style.display = 'block';
                modalFooter.style.display = 'flex';
            }
        } catch (err) {
            alert(err);
        } finally {
            document.getElementById('btnGenStandard').disabled = false;
            document.getElementById('btnGenManual').disabled = false;
            loadingView.style.display = 'none';
        }
    };

    document.getElementById('btnGenStandard').addEventListener('click', () => processReport('standard'));
    document.getElementById('btnGenManual').addEventListener('click', async () => {
        try {
            const res = await fetch('/api/logs');
            const logs = await res.json();
            const log = logs.find(l => l.id === currentLogIdForReport);
            if (log) {
                manualEditor.value = getManualTemplate(log);
                selectionView.style.display = 'none';
                manualView.style.display = 'block';
            }
        } catch (err) {
            alert(err);
        }
    });

    document.getElementById('btnBackToSelection').addEventListener('click', () => {
        manualView.style.display = 'none';
        selectionView.style.display = 'block';
    });

    document.getElementById('btnSubmitManual').addEventListener('click', () => {
        const content = manualEditor.value;
        if (!content.trim()) {
            alert("Konten laporan tidak boleh kosong.");
            return;
        }
        processReport('manual', content);
    });

    document.getElementById('btnDownloadPDF').addEventListener('click', () => {
        const opt = {
            margin: [15, 15, 15, 15],
            filename: `Incident_Report_${currentLogIdForReport}.pdf`,
            image: { type: 'jpeg', quality: 0.98 },
            html2canvas: { scale: 2, logging: false },
            jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' },
            pagebreak: { mode: ['avoid-all', 'css', 'legacy'] }
        };
        html2pdf().set(opt).from(pdfPrintableArea).save();
    });

    fetchStats();
    fetchLogs();
    fetchReports();

    setInterval(() => {
        fetch('/api/generate_log', { method: 'POST' }).then(res => res.json()).then(data => {
            updateStats(data.stats);
            if (!logIds.has(data.log.id)) {
                logIds.add(data.log.id);
                renderLog(data.log);
            }
        }).catch(err => console.error(err));
    }, 4000);
});
