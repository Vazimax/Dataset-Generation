#!/bin/bash
# Monitor raw variant generation progress

OUTPUT="raw_variants_1000.json"
TARGET=1000

echo "Monitoring raw variant generation..."
echo "Target: $TARGET variants"
echo "Press Ctrl+C to stop monitoring"
echo ""

while true; do
    if [ -f "$OUTPUT" ]; then
        COUNT=$(python3 -c "import json; print(len(json.load(open('$OUTPUT'))))" 2>/dev/null || echo "0")
        SIZE=$(du -h "$OUTPUT" 2>/dev/null | cut -f1)
        PERCENT=$(python3 -c "print(f'{($COUNT/$TARGET)*100:.1f}%')" 2>/dev/null || echo "0%")
        
        # Estimate time remaining (rough estimate: ~2-3 seconds per variant)
        REMAINING=$((TARGET - COUNT))
        ETA_SEC=$((REMAINING * 2))
        ETA_MIN=$((ETA_SEC / 60))
        ETA_HOUR=$((ETA_MIN / 60))
        
        echo "[$(date +%H:%M:%S)] Generated: $COUNT/$TARGET ($PERCENT) | Size: $SIZE | ETA: ~${ETA_MIN}m"
        
        if [ "$COUNT" -ge "$TARGET" ]; then
            echo ""
            echo "✓ Generation complete! $COUNT variants generated."
            break
        fi
    else
        echo "[$(date +%H:%M:%S)] Waiting for output file..."
    fi
    
    sleep 30
done

