from PyPDF2 import PdfReader
from datetime import datetime
import pytesseract
from pdf2image import convert_from_path
import fitz
from tqdm import tqdm

class PDFTamperEvaluator:
    """
        Initialize the tamper evaluator with the path to the PDF.
        Set up scoring and suspicious metadata patterns.
    """
    def __init__(self,pdf_path:str):
        self.pdf_path = pdf_path
        self.heuristic_score = 0 # Used to accumulate suspicion score

        # Common suspicious metadata values that could indicate manipulation
        self.SUSPICIOUS_METADATA = {
            "authors": {
                "user", "admin", "unknown", "anonymous", "test", "example", "scanner",
                "editor", "creator", "demo", "temp", "student", "pdf user", "system",
                "me", "doc editor", "office user", "sample", "root", "default", "guest",
                "ilovepdf", "sejda", "wps", "foxit", "nitro", "pdffiller", "pdfescape",
                "john doe", "microsoft", "libreoffice", "openoffice", "someone",
                "123", "abc", "scanned", "modified", "not known", "none"
            },

            "producers": {
                "ilovepdf", "smallpdf", "sejda", "foxit pdf editor", "foxit reader",
                "nitro pro", "pdfsam", "pdf24 creator", "pdf-xchange", "pdf-xchange editor",
                "wps pdf", "libreoffice", "openoffice", "microsoft word", "pdf architect",
                "pdffiller", "pdfescape", "freepdf", "soda pdf", "cvision", "scansoft",
                "pdfedit", "pdf candy", "able2extract", "image to pdf converter",
                "online2pdf", "dompdf", "wkhtmltopdf", "princexml", "python-pdfkit",
                "jsPDF", "html2pdf", "novaPDF", "icecream pdf editor", "easy pdf",
                "cam scanner", "scanner app", "tinywow", "qoppa pdf", "pdfgear",
                "onlineconvert", "convertio", "pdfcrowd", "docupub", "phantompdf",
                "scan2pdf", "bullzip", "scanbot", "drawboard pdf", "xodo pdf",
                "kdan pdf reader", "apowersoft pdf converter", "gimp pdf", "inkscape pdf",
                "cutePDF", "verypdf", "naps2", "jpeg to pdf", "png to pdf", "pdf reducer",
                "4-heights™ pdf library 3.4.0.6904 (http://www.pdf-tools.com)"
            },

            "creators": {
                "microsoft word", "word for mac", "microsoft office", "office word",
                "wps office", "wps writer", "libreoffice", "openoffice", "pdf-xchange",
                "foxit pdf editor", "foxit reader", "ilovepdf", "smallpdf", "sejda",
                "pdfescape", "pdffiller", "pdf architect", "pdf candy", "soda pdf",
                "pdfgear", "pdfsam", "online2pdf", "dompdf", "wkhtmltopdf", "princexml",
                "python-pdfkit", "reportlab", "jspdf", "html2pdf", "scan2pdf",
                "scanner app", "camscanner", "gimp", "inkscape", "cutePDF", "verypdf",
                "image to pdf", "jpeg to pdf", "png to pdf", "icecream pdf editor",
                "novaPDF", "xodo pdf", "drawboard pdf", "phantompdf", "bullzip",
                "easy pdf", "convertio", "apowersoft pdf converter", "qoppa pdf studio",
                "naps2", "freepdf", "scansoft", "able2extract", "tinywow", "pdf converter"
            }
        }
        # Mapping of metadata keys for lookup
        self.PDF_META_KEYS = {
            "authors": "/Author",
            "producers": "/Producer",
            "creators": "/Creator"
        }

    def add_score(self, points):
        """Add given score to the overall heuristic score."""
        self.heuristic_score += points
        
    def check_suspicious_metadata(self):
        """
        Check PDF metadata fields for suspicious authors, producers, and creators.
        Also, compare creation and modification dates.
        """
        for _ in tqdm(range(1), desc="Checking Metadata"):
            score = 0
            metadata_not_available_count = 0

            reader = PdfReader(self.pdf_path)

            try:
                metadata = reader.metadata
            except Exception as e:
                tqdm.write(f"Failed to extract metadata: {e}")
                metadata = {}

            creation_date = None
            mod_date = None

            # Handle creation date
            try:
                creation_str = metadata['/CreationDate']
                if creation_str.startswith("D:"):
                    creation_str = creation_str[2:]
                creation_date = datetime.strptime(creation_str[:14], "%Y%m%d%H%M%S")
            except KeyError:
                metadata_not_available_count += 1
            except Exception as e:
                tqdm.write(f"Error parsing CreationDate: {e}")
                metadata_not_available_count += 1

            # Handle modification date
            try:
                mod_str = metadata['/ModDate']
                if mod_str.startswith("D:"):
                    mod_str = mod_str[2:]
                mod_date = datetime.strptime(mod_str[:14], "%Y%m%d%H%M%S")
            except KeyError:
                metadata_not_available_count += 1
            except Exception as e:
                tqdm.write(f"Error parsing ModDate: {e}")
                metadata_not_available_count += 1

            # Analyze the dates
            if mod_date and creation_date or (mod_date and not creation_date):
                if mod_date != creation_date:
                    score += 0.1
                    tqdm.write("Warning: Modification date differs from creation date.")
                else:
                    tqdm.write("Modification date and creation date are the same.")
            elif not creation_date:
                tqdm.write("Creation date not available.")
            elif not mod_date:
                tqdm.write("Modification date not available.")

            results = []
            # Check for known suspicious metadata values
            for key, values in self.SUSPICIOUS_METADATA.items():
        
                pdf_meta_key = self.PDF_META_KEYS.get(key)
                if not pdf_meta_key:
                    continue
                meta_field = metadata.get(pdf_meta_key, "").lower()
                if not meta_field:
                    metadata_not_available_count += 1
                for val in values:
                    if val in meta_field:
                        results.append(f" Suspicious {key[:-1]} detected: '{meta_field}' matches '{val}'")
            # Increase score for suspicious values and missing metadata
            score += min(len(results)*0.05,0.15)
            score += min(metadata_not_available_count*0.0125,0.05)

            # Add meta data analysis to the global heuristic score
            self.add_score(score)
            print(metadata)

            tqdm.write(str(score))
    
    #Detect without over-lays in pdf
    def detect_whiteout_overlays(self):
        """
        Detect white rectangles drawn on top of PDF content (commonly used to hide or mask data).
        """
        for _ in tqdm(range(1), desc="Detecting White Boxes"):
            score = 0
            suspicious_area_count = 0
            doc = fitz.open(self.pdf_path)
             # Loop through each page and analyze drawing objects
            for page_num, page in enumerate(doc):
                drawings = page.get_drawings()
                white_boxes = [d for d in drawings if d['fill'] == (1.0, 1.0, 1.0)]
                if white_boxes:
                    suspicious_area_count += len(white_boxes)
            
            # Assign score based on number of whiteout boxes found
            score =  min(suspicious_area_count * 0.035,0.35)
            self.add_score(score)
            tqdm.write(str(score))
    
    #Compare hidden text using ocr and pdf_text
    def extract_pdf_text(self):
        """Extract machine-readable text from the PDF using PyPDF2."""
        reader = PdfReader(self.pdf_path)
        return "\n".join([page.extract_text() or '' for page in reader.pages])

    def extract_ocr_text(self):
        """Convert each PDF page to image and extract text using OCR (Tesseract)."""
        images = convert_from_path(self.pdf_path)
        text = ''
        for img in images:
            text += pytesseract.image_to_string(img)
        return text

    def compare_pdf_and_ocr(self):
        """
        Compare text extracted from the PDF layer and OCR layer.
        A significant mismatch could indicate hidden or edited content.
        """
        for _ in tqdm(range(1), desc="Comparing OCR vs PDF Text"):
            pdf_text = self.extract_pdf_text()
            ocr_text = self.extract_ocr_text()
            tolerance = 10
            score = 0

            ocr_len = len(ocr_text)
            pdf_len = len(pdf_text)
            text_diff = abs(ocr_len - pdf_len)

            # Ignore small difference under tolerance
            if(text_diff > tolerance):
                text_diff = text_diff - tolerance

            # Normalize by max length to scale mismatch
            max_len = ocr_len
            mismatch_ratio = text_diff / max_len

            # Final score: scale to max_score, but cap at max_score
            score +=  min(mismatch_ratio * 0.35,0.35)

            # Now add it the global heuristic score

            self.add_score(score)
            tqdm.write(str(score))
        
    def check_document(self):
        """
        Run all analysis modules and return final suspicion score and verdict.
        """
        self.check_suspicious_metadata()
        self.detect_whiteout_overlays()
        self.compare_pdf_and_ocr()

        final_score = round(self.heuristic_score * 100, 2)

        if final_score >= 60:
            verdict = "Highly Suspicious - Likely Tampered"
        elif final_score >=30:
            verdict = "Moderately Suspicious Possible - Tampering"
        else:
            verdict = "Low Suspicion - Likely Untampered"

        return final_score, verdict

        
    

        