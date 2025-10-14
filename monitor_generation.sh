#!/bin/bash
# Monitor generation progress

OUTPUT="large_dataset_1000.json"

echo "Monitoring generation progress..."
echo "Press Ctrl+C to stop monitoring"
echo ""

while true; do
    if [ -f "$OUTPUT" ]; then
        COUNT=$(python3 -c "import json; print(len(json.load(open('$OUTPUT'))))" 2>/dev/null || echo "0")
        SIZE=$(du -h "$OUTPUT" 2>/dev/null | cut -f1)
        echo "[$(date +%H:%M:%S)] Generated: $COUNT variants | Size: $SIZE"
        
        if [ "$COUNT" -ge 1000 ]; then
            echo ""
            echo "✓ Generation complete! 1000 variants generated."
            break
        fi
    else
        echo "[$(date +%H:%M:%S)] Waiting for output file..."
    fi
    
    sleep 10
done

