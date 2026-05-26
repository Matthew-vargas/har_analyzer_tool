"""
HAR Privacy Analyzer - Application Entry Point
"""

from backend import app
import os

if __name__ == '__main__':
    if not os.path.exists('static'):
        os.makedirs('static')

    port = int(os.environ.get('PORT', 5000))

    print(f"\n{'='*60}")
    print(f"HAR Privacy Analyzer")
    print(f"{'='*60}")
    print(f"Static folder: {os.path.join(os.getcwd(), 'static')}")
    print(f"Server:        http://localhost:{port}")
    print(f"Max upload:    600 MB (bulk batch)")
    print(f"{'='*60}\n")

    app.run(host='0.0.0.0', port=port, debug=False)
