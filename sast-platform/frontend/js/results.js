function escapeHtml(value) {
	const text = String(value ?? "");
	return text
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}

function severityBadgeClass(severity) {
	const normalized = String(severity || "LOW").toUpperCase();
	if (normalized === "HIGH") return "severity-badge severity-high";
	if (normalized === "MEDIUM") return "severity-badge severity-medium";
	return "severity-badge severity-low";
}

function normalizeSummary(summary) {
	return {
		HIGH: Number(summary?.HIGH || 0),
		MEDIUM: Number(summary?.MEDIUM || 0),
		LOW: Number(summary?.LOW || 0),
	};
}

function renderScanResults(report, target = "results") {
	const container = typeof target === "string" ? document.getElementById(target) : target;
	if (!container) return;

	const findings = Array.isArray(report?.findings) ? report.findings : [];
	const summary = normalizeSummary(report?.summary || {});
	const vulnCount = Number(report?.vuln_count ?? findings.length);
	const scanId = escapeHtml(report?.scan_id || "-");
	const tool = escapeHtml(report?.tool || "-");
	const language = escapeHtml(report?.language || "-");

	const rows = findings
		.map((finding) => {
			const severity = String(finding?.severity || "LOW").toUpperCase();
			const confidence = escapeHtml(finding?.confidence || "UNKNOWN");
			const issue = escapeHtml(finding?.issue || "Unknown issue");
			const line = Number(finding?.line ?? 0);
			const snippet = escapeHtml(finding?.code_snippet || "");
			const ruleId = escapeHtml(finding?.rule_id || "UNKNOWN");

			return `
				<tr>
					<td><span class="${severityBadgeClass(severity)}">${severity}</span></td>
					<td>${confidence}</td>
					<td>${line}</td>
					<td>${ruleId}</td>
					<td>${issue}</td>
					<td><pre>${snippet}</pre></td>
				</tr>
			`;
		})
		.join("");

	container.innerHTML = `
		<section class="result-meta">
			<p><strong>Scan ID:</strong> ${scanId}</p>
			<p><strong>Language:</strong> ${language}</p>
			<p><strong>Tool:</strong> ${tool}</p>
			<p><strong>Total:</strong> ${vulnCount}</p>
		</section>

		<section class="result-summary">
			<span class="${severityBadgeClass("HIGH")}">HIGH ${summary.HIGH}</span>
			<span class="${severityBadgeClass("MEDIUM")}">MEDIUM ${summary.MEDIUM}</span>
			<span class="${severityBadgeClass("LOW")}">LOW ${summary.LOW}</span>
		</section>

		<section class="result-findings">
			<table>
				<thead>
					<tr>
						<th>Severity</th>
						<th>Confidence</th>
						<th>Line</th>
						<th>Rule</th>
						<th>Issue</th>
						<th>Code Snippet</th>
					</tr>
				</thead>
				<tbody>
					${rows || '<tr><td colspan="6">No findings.</td></tr>'}
				</tbody>
			</table>
		</section>
	`;
}

window.renderScanResults = renderScanResults;

