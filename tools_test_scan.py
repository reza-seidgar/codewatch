import sys
sys.path.insert(0, r'E:\Drive E\work\strix\codewatch')
from app.agents.tools.file_scanner import scan_project_structure
r = scan_project_structure('app')
print('dir_tree_len=', len(r['directory_tree']))
print('dep_total=', sum(len(v) for v in r['dependency_files_content'].values()))
print(list(r['dependency_files_content'].keys()))
