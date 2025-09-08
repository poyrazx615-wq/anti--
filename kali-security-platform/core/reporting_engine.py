# Advanced Reporting Engine for Security Assessment Results
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import jinja2
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.pdfgen import canvas
import base64
from io import BytesIO

class ReportFormat(Enum):
    """Report output formats"""
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    EXCEL = "excel"
    MARKDOWN = "markdown"
    XML = "xml"

class ReportType(Enum):
    """Report types"""
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"
    VULNERABILITY = "vulnerability"
    PENETRATION = "penetration"
    INCIDENT = "incident"
    AUDIT = "audit"

@dataclass
class ReportSection:
    """Report section"""
    title: str
    content: Any
    section_type: str = "text"  # text, table, chart, image
    level: int = 1
    page_break: bool = False

@dataclass
class ReportTemplate:
    """Report template definition"""
    name: str
    type: ReportType
    sections: List[str]
    style: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

class ReportGenerator:
    """Generate professional security reports"""
    
    def __init__(self):
        self.templates = {}
        self.styles = {}
        self._load_templates()
        self._setup_styles()
    
    def _load_templates(self):
        """Load report templates"""
        
        self.templates = {
            "executive_summary": ReportTemplate(
                name="Executive Summary",
                type=ReportType.EXECUTIVE,
                sections=[
                    "cover_page",
                    "executive_overview",
                    "risk_summary",
                    "key_findings",
                    "recommendations",
                    "conclusion"
                ],
                style={"color_scheme": "professional", "charts": True}
            ),
            "technical_report": ReportTemplate(
                name="Technical Report",
                type=ReportType.TECHNICAL,
                sections=[
                    "cover_page",
                    "table_of_contents",
                    "methodology",
                    "technical_findings",
                    "vulnerability_details",
                    "exploitation_results",
                    "recommendations",
                    "appendix"
                ],
                style={"color_scheme": "technical", "code_blocks": True}
            ),
            "compliance_report": ReportTemplate(
                name="Compliance Report",
                type=ReportType.COMPLIANCE,
                sections=[
                    "cover_page",
                    "compliance_summary",
                    "standards_assessed",
                    "compliance_status",
                    "gaps_identified",
                    "remediation_plan",
                    "attestation"
                ],
                style={"color_scheme": "formal", "tables": True}
            ),
            "vulnerability_assessment": ReportTemplate(
                name="Vulnerability Assessment",
                type=ReportType.VULNERABILITY,
                sections=[
                    "cover_page",
                    "assessment_scope",
                    "vulnerability_summary",
                    "detailed_vulnerabilities",
                    "risk_matrix",
                    "remediation_priority",
                    "conclusion"
                ],
                style={"color_scheme": "security", "risk_charts": True}
            )
        }
    
    def _setup_styles(self):
        """Setup report styles"""
        
        self.styles = getSampleStyleSheet()
        
        # Custom styles
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            textColor=colors.HexColor('#1e3a8a'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor('#2563eb'),
            spaceAfter=12,
            spaceBefore=12
        ))
        
        self.styles.add(ParagraphStyle(
            name='Finding',
            parent=self.styles['Normal'],
            fontSize=11,
            leftIndent=20,
            spaceAfter=6
        ))
    
    async def generate_report(
        self,
        report_type: ReportType,
        data: Dict[str, Any],
        format: ReportFormat = ReportFormat.PDF,
        template: str = None,
        custom_sections: List[ReportSection] = None
    ) -> bytes:
        """Generate a report"""
        
        # Select template
        if template and template in self.templates:
            report_template = self.templates[template]
        else:
            # Auto-select based on report type
            report_template = self._select_template(report_type)
        
        # Build report content
        sections = []
        for section_name in report_template.sections:
            section_content = await self._generate_section(section_name, data)
            if section_content:
                sections.append(section_content)
        
        # Add custom sections
        if custom_sections:
            sections.extend(custom_sections)
        
        # Generate output based on format
        if format == ReportFormat.PDF:
            return self._generate_pdf(sections, data, report_template)
        elif format == ReportFormat.HTML:
            return self._generate_html(sections, data, report_template)
        elif format == ReportFormat.JSON:
            return self._generate_json(sections, data)
        elif format == ReportFormat.CSV:
            return self._generate_csv(data)
        elif format == ReportFormat.EXCEL:
            return self._generate_excel(sections, data)
        elif format == ReportFormat.MARKDOWN:
            return self._generate_markdown(sections, data)
        elif format == ReportFormat.XML:
            return self._generate_xml(sections, data)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    async def _generate_section(self, section_name: str, data: Dict) -> Optional[ReportSection]:
        """Generate a report section"""
        
        if section_name == "cover_page":
            return self._create_cover_page(data)
        elif section_name == "executive_overview":
            return self._create_executive_overview(data)
        elif section_name == "risk_summary":
            return self._create_risk_summary(data)
        elif section_name == "key_findings":
            return self._create_key_findings(data)
        elif section_name == "technical_findings":
            return self._create_technical_findings(data)
        elif section_name == "vulnerability_details":
            return self._create_vulnerability_details(data)
        elif section_name == "recommendations":
            return self._create_recommendations(data)
        elif section_name == "risk_matrix":
            return self._create_risk_matrix(data)
        else:
            return None
    
    def _create_cover_page(self, data: Dict) -> ReportSection:
        """Create cover page"""
        content = {
            "title": data.get("report_title", "Security Assessment Report"),
            "subtitle": data.get("target", ""),
            "date": datetime.utcnow().strftime("%B %d, %Y"),
            "prepared_for": data.get("client", ""),
            "prepared_by": data.get("assessor", "Security Team"),
            "classification": data.get("classification", "CONFIDENTIAL")
        }
        
        return ReportSection(
            title="Cover Page",
            content=content,
            section_type="cover",
            page_break=True
        )
    
    def _create_executive_overview(self, data: Dict) -> ReportSection:
        """Create executive overview"""
        
        overview = []
        overview.append(f"This report presents the findings of the security assessment conducted on {data.get('target', 'the target system')}.")
        overview.append(f"The assessment was performed between {data.get('start_date', 'N/A')} and {data.get('end_date', 'N/A')}.")
        
        stats = data.get("statistics", {})
        if stats:
            overview.append(f"During the assessment, {stats.get('total_tests', 0)} tests were performed, "
                          f"identifying {stats.get('total_vulnerabilities', 0)} vulnerabilities.")
        
        return ReportSection(
            title="Executive Overview",
            content="\n\n".join(overview),
            section_type="text"
        )
    
    def _create_risk_summary(self, data: Dict) -> ReportSection:
        """Create risk summary"""
        
        vulnerabilities = data.get("vulnerabilities", [])
        
        # Count by severity
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Info")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Create risk chart
        chart = self._create_risk_chart(severity_counts)
        
        return ReportSection(
            title="Risk Summary",
            content={
                "counts": severity_counts,
                "chart": chart,
                "overall_risk": self._calculate_overall_risk(severity_counts)
            },
            section_type="chart"
        )
    
    def _create_key_findings(self, data: Dict) -> ReportSection:
        """Create key findings section"""
        
        findings = []
        vulnerabilities = data.get("vulnerabilities", [])
        
        # Get top critical/high vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v.get("severity") in ["Critical", "High"]]
        
        for vuln in critical_vulns[:5]:  # Top 5
            findings.append({
                "title": vuln.get("title", "Unknown Vulnerability"),
                "severity": vuln.get("severity"),
                "description": vuln.get("description", ""),
                "impact": vuln.get("impact", ""),
                "affected": vuln.get("affected_components", [])
            })
        
        return ReportSection(
            title="Key Findings",
            content=findings,
            section_type="findings"
        )
    
    def _create_technical_findings(self, data: Dict) -> ReportSection:
        """Create technical findings section"""
        
        technical_data = []
        vulnerabilities = data.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            technical_data.append({
                "id": vuln.get("id"),
                "title": vuln.get("title"),
                "cve": vuln.get("cve"),
                "cvss": vuln.get("cvss_score"),
                "description": vuln.get("technical_description"),
                "poc": vuln.get("proof_of_concept"),
                "references": vuln.get("references", [])
            })
        
        return ReportSection(
            title="Technical Findings",
            content=technical_data,
            section_type="technical"
        )
    
    def _create_vulnerability_details(self, data: Dict) -> ReportSection:
        """Create detailed vulnerability section"""
        
        vulnerabilities = data.get("vulnerabilities", [])
        detailed_vulns = []
        
        for vuln in vulnerabilities:
            detailed_vulns.append({
                "id": vuln.get("id"),
                "title": vuln.get("title"),
                "severity": vuln.get("severity"),
                "cvss_score": vuln.get("cvss_score"),
                "cve": vuln.get("cve"),
                "description": vuln.get("description"),
                "technical_details": vuln.get("technical_details"),
                "affected_systems": vuln.get("affected_systems", []),
                "evidence": vuln.get("evidence"),
                "impact": vuln.get("impact"),
                "likelihood": vuln.get("likelihood"),
                "remediation": vuln.get("remediation"),
                "references": vuln.get("references", [])
            })
        
        return ReportSection(
            title="Vulnerability Details",
            content=detailed_vulns,
            section_type="vulnerabilities",
            page_break=True
        )
    
    def _create_recommendations(self, data: Dict) -> ReportSection:
        """Create recommendations section"""
        
        recommendations = data.get("recommendations", [])
        
        if not recommendations:
            # Generate automatic recommendations based on vulnerabilities
            vulnerabilities = data.get("vulnerabilities", [])
            recommendations = self._generate_recommendations(vulnerabilities)
        
        # Organize by priority
        priority_recs = {
            "Immediate": [],
            "Short-term": [],
            "Long-term": []
        }
        
        for rec in recommendations:
            priority = rec.get("priority", "Long-term")
            if priority in priority_recs:
                priority_recs[priority].append(rec)
        
        return ReportSection(
            title="Recommendations",
            content=priority_recs,
            section_type="recommendations"
        )
    
    def _create_risk_matrix(self, data: Dict) -> ReportSection:
        """Create risk matrix"""
        
        vulnerabilities = data.get("vulnerabilities", [])
        
        # Create risk matrix data
        matrix = {
            "Critical": {"Low": 0, "Medium": 0, "High": 0},
            "High": {"Low": 0, "Medium": 0, "High": 0},
            "Medium": {"Low": 0, "Medium": 0, "High": 0},
            "Low": {"Low": 0, "Medium": 0, "High": 0}
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Low")
            likelihood = vuln.get("likelihood", "Low")
            if severity in matrix and likelihood in matrix[severity]:
                matrix[severity][likelihood] += 1
        
        # Create visual matrix
        matrix_image = self._create_risk_matrix_image(matrix)
        
        return ReportSection(
            title="Risk Matrix",
            content={
                "matrix": matrix,
                "image": matrix_image
            },
            section_type="matrix"
        )
    
    def _create_risk_chart(self, severity_counts: Dict) -> str:
        """Create risk distribution chart"""
        
        fig, ax = plt.subplots(figsize=(8, 6))
        
        colors_map = {
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#facc15",
            "Low": "#84cc16",
            "Info": "#06b6d4"
        }
        
        labels = list(severity_counts.keys())
        values = list(severity_counts.values())
        colors_list = [colors_map[label] for label in labels]
        
        ax.pie(values, labels=labels, colors=colors_list, autopct='%1.1f%%')
        ax.set_title("Risk Distribution")
        
        # Convert to base64
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode()
        plt.close()
        
        return image_base64
    
    def _create_risk_matrix_image(self, matrix: Dict) -> str:
        """Create risk matrix visualization"""
        
        fig, ax = plt.subplots(figsize=(10, 8))
        
        # Create heatmap data
        import numpy as np
        data = np.array([
            [matrix["Critical"]["Low"], matrix["Critical"]["Medium"], matrix["Critical"]["High"]],
            [matrix["High"]["Low"], matrix["High"]["Medium"], matrix["High"]["High"]],
            [matrix["Medium"]["Low"], matrix["Medium"]["Medium"], matrix["Medium"]["High"]],
            [matrix["Low"]["Low"], matrix["Low"]["Medium"], matrix["Low"]["High"]]
        ])
        
        sns.heatmap(data, annot=True, fmt='d', cmap='RdYlGn_r',
                   xticklabels=["Low", "Medium", "High"],
                   yticklabels=["Critical", "High", "Medium", "Low"])
        
        ax.set_xlabel("Likelihood")
        ax.set_ylabel("Impact")
        ax.set_title("Risk Matrix")
        
        # Convert to base64
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode()
        plt.close()
        
        return image_base64
    
    def _calculate_overall_risk(self, severity_counts: Dict) -> str:
        """Calculate overall risk level"""
        
        risk_score = (
            severity_counts.get("Critical", 0) * 10 +
            severity_counts.get("High", 0) * 5 +
            severity_counts.get("Medium", 0) * 2 +
            severity_counts.get("Low", 0) * 1
        )
        
        if risk_score >= 50:
            return "CRITICAL"
        elif risk_score >= 25:
            return "HIGH"
        elif risk_score >= 10:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate automatic recommendations based on vulnerabilities"""
        
        recommendations = []
        
        # Analyze vulnerability types
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "Unknown")
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        # Generate recommendations by type
        for vuln_type, vulns in vuln_types.items():
            if vuln_type == "SQL Injection":
                recommendations.append({
                    "title": "Implement Parameterized Queries",
                    "description": "Use prepared statements and parameterized queries to prevent SQL injection",
                    "priority": "Immediate",
                    "effort": "Medium"
                })
            elif vuln_type == "XSS":
                recommendations.append({
                    "title": "Implement Output Encoding",
                    "description": "Encode all user input before displaying in HTML context",
                    "priority": "Immediate",
                    "effort": "Low"
                })
            # Add more recommendation logic
        
        return recommendations
    
    def _select_template(self, report_type: ReportType) -> ReportTemplate:
        """Select appropriate template based on report type"""
        
        template_map = {
            ReportType.EXECUTIVE: "executive_summary",
            ReportType.TECHNICAL: "technical_report",
            ReportType.COMPLIANCE: "compliance_report",
            ReportType.VULNERABILITY: "vulnerability_assessment"
        }
        
        template_name = template_map.get(report_type, "technical_report")
        return self.templates[template_name]
    
    def _generate_pdf(self, sections: List[ReportSection], data: Dict, template: ReportTemplate) -> bytes:
        """Generate PDF report"""
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        elements = []
        
        for section in sections:
            if section.section_type == "cover":
                elements.extend(self._create_pdf_cover(section.content))
            elif section.section_type == "text":
                elements.append(Paragraph(section.title, self.styles['SectionHeader']))
                elements.append(Paragraph(section.content, self.styles['Normal']))
                elements.append(Spacer(1, 12))
            elif section.section_type == "findings":
                elements.extend(self._create_pdf_findings(section))
            elif section.section_type == "vulnerabilities":
                elements.extend(self._create_pdf_vulnerabilities(section))
            
            if section.page_break:
                elements.append(PageBreak())
        
        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()
    
    def _create_pdf_cover(self, content: Dict) -> List:
        """Create PDF cover page"""
        elements = []
        
        elements.append(Spacer(1, 2*inch))
        elements.append(Paragraph(content["title"], self.styles['CustomTitle']))
        elements.append(Paragraph(content["subtitle"], self.styles['Title']))
        elements.append(Spacer(1, 1*inch))
        elements.append(Paragraph(f"Date: {content['date']}", self.styles['Normal']))
        elements.append(Paragraph(f"Prepared for: {content['prepared_for']}", self.styles['Normal']))
        elements.append(Paragraph(f"Prepared by: {content['prepared_by']}", self.styles['Normal']))
        elements.append(Spacer(1, 2*inch))
        elements.append(Paragraph(f"Classification: {content['classification']}", self.styles['Normal']))
        elements.append(PageBreak())
        
        return elements
    
    def _create_pdf_findings(self, section: ReportSection) -> List:
        """Create PDF findings section"""
        elements = []
        
        elements.append(Paragraph(section.title, self.styles['SectionHeader']))
        
        for finding in section.content:
            elements.append(Paragraph(f"• {finding['title']} ({finding['severity']})", self.styles['Finding']))
            elements.append(Paragraph(finding['description'], self.styles['Normal']))
            elements.append(Spacer(1, 6))
        
        return elements
    
    def _create_pdf_vulnerabilities(self, section: ReportSection) -> List:
        """Create PDF vulnerabilities section"""
        elements = []
        
        elements.append(Paragraph(section.title, self.styles['SectionHeader']))
        
        for vuln in section.content:
            # Vulnerability header
            elements.append(Paragraph(f"{vuln['title']} - {vuln['severity']}", self.styles['Heading2']))
            
            # Details table
            data = [
                ["CVSS Score", vuln.get('cvss_score', 'N/A')],
                ["CVE", vuln.get('cve', 'N/A')],
                ["Affected Systems", ', '.join(vuln.get('affected_systems', []))]
            ]
            
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(table)
            elements.append(Spacer(1, 12))
            
            # Description
            elements.append(Paragraph("Description:", self.styles['Heading3']))
            elements.append(Paragraph(vuln.get('description', ''), self.styles['Normal']))
            elements.append(Spacer(1, 6))
            
            # Remediation
            elements.append(Paragraph("Remediation:", self.styles['Heading3']))
            elements.append(Paragraph(vuln.get('remediation', ''), self.styles['Normal']))
            elements.append(Spacer(1, 12))
        
        return elements
    
    def _generate_html(self, sections: List[ReportSection], data: Dict, template: ReportTemplate) -> bytes:
        """Generate HTML report"""
        
        # Load HTML template
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ title }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                h1 { color: #1e3a8a; }
                h2 { color: #2563eb; }
                .finding { margin: 20px 0; padding: 15px; background: #f3f4f6; border-left: 4px solid #2563eb; }
                .critical { border-left-color: #dc2626; }
                .high { border-left-color: #ea580c; }
                .medium { border-left-color: #facc15; }
                .low { border-left-color: #84cc16; }
            </style>
        </head>
        <body>
            {% for section in sections %}
                <h2>{{ section.title }}</h2>
                {{ section.content }}
            {% endfor %}
        </body>
        </html>
        """
        
        template_obj = jinja2.Template(html_template)
        html = template_obj.render(
            title=data.get("report_title", "Security Report"),
            sections=sections
        )
        
        return html.encode('utf-8')
    
    def _generate_json(self, sections: List[ReportSection], data: Dict) -> bytes:
        """Generate JSON report"""
        
        report = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "report_type": data.get("report_type", "security_assessment")
            },
            "data": data,
            "sections": [
                {
                    "title": section.title,
                    "content": section.content,
                    "type": section.section_type
                }
                for section in sections
            ]
        }
        
        return json.dumps(report, indent=2, default=str).encode('utf-8')
    
    def _generate_csv(self, data: Dict) -> bytes:
        """Generate CSV report"""
        
        vulnerabilities = data.get("vulnerabilities", [])
        
        if vulnerabilities:
            df = pd.DataFrame(vulnerabilities)
            return df.to_csv(index=False).encode('utf-8')
        
        return b""
    
    def _generate_excel(self, sections: List[ReportSection], data: Dict) -> bytes:
        """Generate Excel report"""
        
        buffer = BytesIO()
        
        with pd.ExcelWriter(buffer, engine='xlsxwriter') as writer:
            # Summary sheet
            summary_data = {
                "Metric": ["Total Vulnerabilities", "Critical", "High", "Medium", "Low"],
                "Value": [
                    len(data.get("vulnerabilities", [])),
                    sum(1 for v in data.get("vulnerabilities", []) if v.get("severity") == "Critical"),
                    sum(1 for v in data.get("vulnerabilities", []) if v.get("severity") == "High"),
                    sum(1 for v in data.get("vulnerabilities", []) if v.get("severity") == "Medium"),
                    sum(1 for v in data.get("vulnerabilities", []) if v.get("severity") == "Low")
                ]
            }
            
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            # Vulnerabilities sheet
            if data.get("vulnerabilities"):
                vuln_df = pd.DataFrame(data["vulnerabilities"])
                vuln_df.to_excel(writer, sheet_name='Vulnerabilities', index=False)
        
        buffer.seek(0)
        return buffer.getvalue()
    
    def _generate_markdown(self, sections: List[ReportSection], data: Dict) -> bytes:
        """Generate Markdown report"""
        
        markdown = []
        
        # Title
        markdown.append(f"# {data.get('report_title', 'Security Assessment Report')}")
        markdown.append("")
        
        for section in sections:
            markdown.append(f"## {section.title}")
            markdown.append("")
            
            if section.section_type == "text":
                markdown.append(section.content)
            elif section.section_type == "findings":
                for finding in section.content:
                    markdown.append(f"### {finding['title']} - {finding['severity']}")
                    markdown.append(finding['description'])
                    markdown.append("")
            elif section.section_type == "vulnerabilities":
                for vuln in section.content:
                    markdown.append(f"### {vuln['title']}")
                    markdown.append(f"**Severity:** {vuln['severity']}")
                    markdown.append(f"**CVSS:** {vuln.get('cvss_score', 'N/A')}")
                    markdown.append("")
                    markdown.append(vuln.get('description', ''))
                    markdown.append("")
            
            markdown.append("")
        
        return "\n".join(markdown).encode('utf-8')
    
    def _generate_xml(self, sections: List[ReportSection], data: Dict) -> bytes:
        """Generate XML report"""
        
        import xml.etree.ElementTree as ET
        
        root = ET.Element("SecurityReport")
        
        # Metadata
        metadata = ET.SubElement(root, "Metadata")
        ET.SubElement(metadata, "GeneratedAt").text = datetime.utcnow().isoformat()
        ET.SubElement(metadata, "ReportType").text = data.get("report_type", "assessment")
        
        # Sections
        for section in sections:
            section_elem = ET.SubElement(root, "Section")
            ET.SubElement(section_elem, "Title").text = section.title
            ET.SubElement(section_elem, "Type").text = section.section_type
            
            # Content (simplified)
            content_elem = ET.SubElement(section_elem, "Content")
            if isinstance(section.content, str):
                content_elem.text = section.content
            elif isinstance(section.content, dict):
                for key, value in section.content.items():
                    ET.SubElement(content_elem, key).text = str(value)
        
        tree = ET.ElementTree(root)
        buffer = BytesIO()
        tree.write(buffer, encoding='utf-8', xml_declaration=True)
        buffer.seek(0)
        
        return buffer.getvalue()

# Global report generator instance
report_generator = ReportGenerator()
