#!/usr/bin/env python3
"""Strict parser for Mothership-owned ordinary traffic JSONL receipts."""
import argparse,json,pathlib,sys
def fail(message): raise ValueError(message)
def percentile(values,p):
    values=sorted(values)
    return values[min(len(values)-1,max(0,(len(values)*p+99)//100-1))] if values else None
def metric(rows, index=None):
    starts=[int(r["startNs"]) for r in rows]
    ends=[int(r["endNs"]) for r in rows]
    good=[int(r["latencyNs"]) for r in rows if r["success"]]
    duration=max(ends)-min(starts)
    value={"attempts":len(rows),"successes":len(good),"failures":len(rows)-len(good),
           "durationNs":duration,"throughputPerSecond":len(rows)*1e9/duration if duration else None,
           "latencyNs":{"p50":percentile(good,50),"p95":percentile(good,95),"p99":percentile(good,99),"max":max(good) if good else None}}
    if index is not None: value["index"]=index
    return value
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("receipt"); ap.add_argument("--clients",type=int,required=True); ap.add_argument("--requests-per-client",type=int,required=True); ap.add_argument("--bucket",type=int,default=0); ap.add_argument("--label",required=True)
    a=ap.parse_args(); rows=[]; summary=None; diagnostics=[]
    for n,raw in enumerate(pathlib.Path(a.receipt).read_text(errors="replace").splitlines(),1):
        if not raw: continue
        if raw.startswith("{"):
            try: row=json.loads(raw)
            except json.JSONDecodeError as e: fail("malformed JSON receipt line %d: %s"%(n,e))
            if not isinstance(row,dict): fail("non-object JSON receipt")
            if row.get("type")=="summary":
                if summary is not None: fail("multiple traffic summaries")
                summary=row
            elif row.get("type")=="request": rows.append(row)
            else: fail("unknown JSON receipt type")
        else: diagnostics.append({"line":n,"text":raw})
    expected=a.clients*a.requests_per_client
    if summary is None or len(rows)!=expected: fail("expected %d request rows, got %d"%(expected,len(rows)))
    seen=set(); latencies=[]; starts=[]; failures=0; buckets={}
    for row in rows:
        try:
            client,sequence=int(row["client"]),int(row["sequence"]); scheduled,start,end,latency=(int(row[k]) for k in ("scheduledNs","startNs","endNs","latencyNs")); success=row["success"]
        except (KeyError,TypeError,ValueError) as e: fail("malformed request receipt: %s"%e)
        if not(0<=client<a.clients and 0<=sequence<a.requests_per_client) or (client,sequence) in seen: fail("invalid or duplicate request index")
        if end<start or latency!=end-start or scheduled<0: fail("non-monotonic request timing")
        seen.add((client,sequence)); starts.append(start); buckets.setdefault(sequence//a.bucket if a.bucket else 0,[]).append(row)
        if success is True: latencies.append(latency)
        elif success is False: failures+=1
        else: fail("request success is not boolean")
    if len(seen)!=expected: fail("request schedule incomplete")
    if int(summary.get("clients",-1))!=a.clients or int(summary.get("requestsPerClient",-1))!=a.requests_per_client or int(summary.get("attempts",-1))!=expected: fail("summary cardinality conflicts with receipts")
    if int(summary.get("successes",-1))!=len(latencies) or int(summary.get("failures",-1))!=failures: fail("summary counts conflict with receipts")
    bucket_metrics=[]
    for index,values in sorted(buckets.items()):
        sequences=set(int(r["sequence"]) for r in values)
        first=index*a.bucket if a.bucket else 0
        expected_sequences=min(a.bucket,a.requests_per_client-first) if a.bucket else a.requests_per_client
        if len(values)!=a.clients*expected_sequences or sequences!=set(range(first,first+expected_sequences)):
            fail("bucket %d cardinality is incomplete"%index)
        bucket_metrics.append(metric(values,index))
    whole=metric(rows)
    whole.update({"schema":1,"label":a.label,"diagnosticLines":diagnostics,"buckets":bucket_metrics})
    print(json.dumps(whole,sort_keys=True,separators=(",",":")))
    return 0 if failures==0 else 1
try: raise SystemExit(main())
except (OSError,ValueError) as e: print("ordinary-traffic-metrics: "+str(e),file=sys.stderr); raise SystemExit(1)
