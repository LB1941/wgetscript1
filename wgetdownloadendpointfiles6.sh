#!/bin/bash

# Set endpoint limit
endpoint_limit=1000

# SecLists paths and patterns
SECLISTS="/usr/share/seclists"

# Function to find relevant SecLists
find_relevant_lists() {
    echo "Finding relevant SecLists..."
    
    if [ ! -d "$SECLISTS" ]; then
        echo "SecLists not found in Kali. Please install: apt-get install seclists"
        return 1
    fi
    
    # Known sensitive patterns
    SENSITIVE_PATTERNS=(
        # File types
        "\.conf$" "\.config$" "\.json$" "\.xml$" "\.env$" "\.ini$" "\.yml$"
        "\.xlsx$" "\.xls$" "\.doc$" "\.pdf$" "\.key$" "\.pem$" "\.cfg$"
        
        # File names
        "account" "admin" "backup" "config" "credential" "database" "dump"
        "password" "private" "secret" "secure" "token" "user" "wallet"
        "apikey" "auth" "oauth" "login" "session" "identity" "personal"
        
        # Common patterns
        "_key" "_token" "_secret" "_password" "_credential"
        "-key" "-token" "-secret" "-password" "-credential"
        "\.key" "\.token" "\.secret" "\.password" "\.credential"
    )
    
    echo "Searching for lists with sensitive patterns..."
    RELEVANT_LISTS=()
    
    for pattern in "${SENSITIVE_PATTERNS[@]}"; do
        found_lists=($(find "$SECLISTS" -type f -name "*.txt" -exec grep -l "$pattern" {} \; 2>/dev/null))
        if [ ${#found_lists[@]} -gt 0 ]; then
            RELEVANT_LISTS+=("${found_lists[@]}")
        fi
    done
    
    # Remove duplicates
    RELEVANT_LISTS=($(printf "%s\n" "${RELEVANT_LISTS[@]}" | sort -u))
    
    # Verify and score lists for relevance
    declare -A LIST_SCORES
    for list in "${RELEVANT_LISTS[@]}"; do
        score=0
        [[ "$list" =~ "Web-Content" ]] && ((score+=5))
        [[ "$list" =~ "sensitive" ]] && ((score+=3))
        [[ "$list" =~ "api" ]] && ((score+=3))
        
        if grep -q -E "(password|token|key|secret|credential)" "$list" 2>/dev/null; then
            ((score+=5))
        fi
        LIST_SCORES["$list"]=$score
    done
    
    # Select top scoring lists
    FINAL_LISTS=()
    for list in "${!LIST_SCORES[@]}"; do
        if [ "${LIST_SCORES[$list]}" -ge 8 ]; then
            FINAL_LISTS+=("$list")
        fi
    done
    
    echo "Selected ${#FINAL_LISTS[@]} highly relevant lists for analysis"
    return 0
}

# Function to calculate sensitivity score
calculate_sensitivity() {
    local url="$1"
    local score=0
    
    # Extract file extension and path components
    local ext="${url##*.}"
    local path="${url//https:\/\//}"
    path="${path//http:\/\//}"
    
    # Base scoring
    case "$ext" in
        json) 
            if [[ "$path" =~ (config|secrets|credentials|auth).json ]]; then
                score=$((score + 50))
            else
                score=$((score + 40))
            fi
            ;;
        yaml|yml) score=$((score + 45));;
        env|conf) score=$((score + 45));;
        xml) score=$((score + 30));;
        txt) 
            if [[ "$path" =~ (password|secret|key|token) ]]; then
                score=$((score + 40))
            else
                score=$((score + 20))
            fi
            ;;
        xlsx|xls) score=$((score + 35));;
        pdf) 
            if [[ "$path" =~ (security|confidential|internal) ]]; then
                score=$((score + 30))
            else
                score=$((score + 15))
            fi
            ;;
    esac
    
    # Path component scoring
    if [[ "$path" =~ /api/ ]]; then score=$((score + 30)); fi
    if [[ "$path" =~ /admin/ ]]; then score=$((score + 30)); fi
    if [[ "$path" =~ /config/ ]]; then score=$((score + 25)); fi
    if [[ "$path" =~ /security/ ]]; then score=$((score + 25)); fi
    if [[ "$path" =~ /internal/ ]]; then score=$((score + 20)); fi
    if [[ "$path" =~ /.well-known/ ]]; then score=$((score + 15)); fi
    
    # Check against SecLists patterns if FINAL_LISTS is defined
    if [ ${#FINAL_LISTS[@]} -gt 0 ]; then
        for list in "${FINAL_LISTS[@]}"; do
            if [ -f "$list" ] && grep -q -i -f "$list" <<< "$path" 2>/dev/null; then
                score=$((score + 25))
                break
            fi
        done
    fi
    
    echo $score
}

# Function to get HTTP response code
get_http_code() {
    local url="$1"
    local http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url")
    echo "$http_code"
}

# Main script starts here
echo "Please enter the path to your .txt file containing URLs:"
read url_file

if [ ! -f "$url_file" ]; then
    echo "Error: File not found!"
    exit 1
fi

# Initialize SecLists
echo "Initializing SecLists analysis..."
find_relevant_lists

# Create necessary files
initial_analysis="initial_analysis.txt"
temp_failed="temp_failed.txt"
failed_file="failedtodownload.txt"
> "$initial_analysis"
> "$temp_failed"
> "$failed_file"

echo "=== PHASE 1: Initial Analysis of First $endpoint_limit Endpoints ==="
count=0

while IFS= read -r url || [ -n "$url" ]; do
    if [[ -z "$url" || "$url" =~ ^[[:space:]]*# ]]; then
        continue
    fi
    
    ((count++))
    
    if [ $count -gt $endpoint_limit ]; then
        echo "Reached $endpoint_limit endpoint limit for initial analysis."
        break
    fi
    
    score=$(calculate_sensitivity "$url")
    echo "$score|$url" >> "$initial_analysis"
    
    if ((count % 100 == 0)); then
        echo "Analyzed $count endpoints..."
    fi
done < "$url_file"

# Sort and display initial analysis
{
    echo -e "\n=== Initial Sensitivity Analysis ==="
    echo "First $endpoint_limit endpoints analyzed for sensitivity"
    echo "Sorted by potential sensitivity score:"
    echo "----------------------------------------"
    
    sort -t'|' -k1 -nr "$initial_analysis" | while IFS='|' read -r score url; do
        echo "Score $score: $url"
    done
} > "$failed_file"

echo -e "\n=== PHASE 2: Download Attempts and Response Analysis ===\n" >> "$failed_file"

# Create downloads directory
mkdir -p downloads

# Statistics counters
total=0
success=0
failed=0
forbidden=0
notfound=0
other=0

echo -e "\nStarting download attempts and response analysis..."

# Process URLs with download attempts
while IFS= read -r url || [ -n "$url" ]; do
    if [[ -z "$url" || "$url" =~ ^[[:space:]]*# ]]; then
        continue
    fi
    
    ((total++))
    
    if [ $total -gt $endpoint_limit ]; then
        echo "Reached $endpoint_limit endpoint limit for download attempts."
        break
    fi
    
    echo "Processing ($total/$endpoint_limit): $url"
    
    http_code=$(get_http_code "$url")
    
    if wget --timeout=10 --tries=1 -q -P downloads "$url" 2>/dev/null; then
        ((success++))
        echo "✓ Success: $url"
    else
        ((failed++))
        case $http_code in
            403) ((forbidden++));;
            404) ((notfound++));;
            *) ((other++));;
        esac
        
        score=$(calculate_sensitivity "$url")
        echo "$score|$url|$http_code" >> "$temp_failed"
        echo "✗ Failed: $url (HTTP $http_code)"
    fi
    
done < "$url_file"

# Add failed downloads analysis
{
    echo -e "\n=== Failed Downloads Analysis ==="
    echo "Sorted by sensitivity score with HTTP response codes:"
    echo "----------------------------------------"
    
    sort -t'|' -k1 -nr "$temp_failed" | while IFS='|' read -r score url code; do
        case $code in
            403) code_display="HTTP 403 (Forbidden)";;
            404) code_display="HTTP 404 (Not Found)";;
            *) code_display="HTTP $code";;
        esac
        echo "Score $score: $url [$code_display]"
    done
    
    echo -e "\n=== Final Analysis Summary ==="
    echo "Total URLs Processed: $total"
    echo "Successfully Downloaded: $success"
    echo "Failed Downloads: $failed"
    echo "  - HTTP 403 (Forbidden): $forbidden"
    echo "  - HTTP 404 (Not Found): $notfound"
    echo "  - Other Status Codes: $other"
} >> "$failed_file"

# Cleanup
rm -f "$temp_failed"
rm -f "$initial_analysis"

# Print final summary to terminal
echo -e "\n=== Analysis Complete ==="
echo "Total URLs Processed: $total"
echo "Successfully Downloaded: $success"
echo "Failed Downloads: $failed"
echo "  - HTTP 403 (Forbidden): $forbidden"
echo "  - HTTP 404 (Not Found): $notfound"
echo "  - Other Status Codes: $other"
echo -e "\nComplete analysis saved to: $failed_file"

# Check for high-sensitivity endpoints
high_risk=$(grep -c "Score [89][0-9]:" "$failed_file")
if [ $high_risk -gt 0 ]; then
    echo -e "\n⚠️  WARNING: Found $high_risk high-sensitivity endpoints (score 80+)"
fi

