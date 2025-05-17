# Import the tamper evaluation class from your module
from lib.pdf_integrity_checker import PDFTamperEvaluator

# Provide the path to the PDF you want to evaluate
# Note: Use raw string (r"") to avoid issues with backslashes in the file path
pdf_eval = PDFTamperEvaluator(r"test_documents\editted_intern_certificate.pdf")

# Run the integrity check on the PDF
# This method performs multiple checks including metadata inspection,
# white box/overlay detection, and OCR vs embedded text comparison
final_score, verdict = pdf_eval.check_document()

# Print out the final tampering score and the corresponding verdict
# The score is based on a weighted heuristic analysis
print(f"Score: {final_score}%")
print(f"Verdict: {verdict}")