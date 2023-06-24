def generate_report(report_data):
    report = ""
    for section, data in report_data.items():
        report += f"{section}\n"
        report += "-" * len(section) + "\n"
        if isinstance(data, list):
            report += "\n".join(data) + "\n"
        else:
            report += str(data) + "\n"
        report += "\n"
    return report
