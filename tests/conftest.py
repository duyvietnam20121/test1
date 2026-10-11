import os
import sys
import tempfile
from pathlib import Path

# Trỏ cấu hình sang thư mục tạm TRƯỚC khi import fleasion.
_TMP = tempfile.mkdtemp(prefix='fleasion-test-')
os.environ['FLEASION_CONFIG_DIR'] = _TMP
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))
