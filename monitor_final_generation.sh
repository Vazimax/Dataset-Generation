#!/bin/bash
# Monitor final generation progress

OUTPUT="final_compiling_1000.json"
TARGET=1000

echo "Monitoring final generation (until $TARGET compiling variants)..."
echo "Press Ctrl+C to stop monitoring"
echo ""

while true; do
    if [ -f "$OUTPUT" ]; then
        COUNT=$(python3 -c "import json; print(len(json.load(open('$OUTPUT'))))" 2>/dev/null || echo "0")
        SIZE=$(du -h "$OUTPUT" 2>/dev/null | cut -f1)
        PERCENT=$(python3 -c "print(f'{($COUNT/$TARGET)*100:.1f}%')" 2>/dev/null || echo "0%")
        
        # Estimate time remaining (rough estimate: ~10-15 seconds per compiling variant)
        REMAINING=$((TARGET - COUNT))
        ETA_SEC=$((REMAINING * 12))
        ETA_MIN=$((ETA_SEC / 60))
        ETA_HOUR=$((ETA_MIN / 60))
        
        if [ "$ETA_HOUR" -gt 0 ]; then
            ETA="${ETA_HOUR}h ${ETA_MIN}m"
        else
            ETA="${ETA_MIN}m"
        fi
        
        echo "[$(date +%H:%M:%S)] Compiling variants: $COUNT/$TARGET ($PERCENT) | Size: $SIZE | ETA: ~$ETA"
        
        if [ "$COUNT" -ge "$TARGET" ]; then
            echo ""
            echo "✓ Generation complete! $COUNT compiling variants generated."
            break
        fi
    else
        echo "[$(date +%H:%M:%S)] Waiting for output file..."
    fi
    
    sleep 30
done

