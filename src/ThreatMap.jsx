import React, { useEffect, useMemo, useState } from "react";
import { CircleMarker, MapContainer, Popup, TileLayer, useMap } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import "./ThreatMap.css";

function FitMarkers({ markers }) {
  const map = useMap();
  useEffect(() => {
    if (!markers.length) return;
    const bounds = L.latLngBounds(markers.map(m => [m.latitude, m.longitude]));
    if (bounds.isValid()) map.fitBounds(bounds.pad(0.22), { maxZoom: 5, animate: true });
  }, [markers, map]);
  return null;
}

function gatherIndicators(cases) {
  const ips = new Set();
  const domains = new Set();
  const urls = new Set();
  for (const item of cases || []) {
    const a = item?.analysis || item?.report || {};
    for (const ip of (Array.isArray(a.ips) ? a.ips : [])) ips.add(String(ip).trim());
    for (const domain of (Array.isArray(a.domains) ? a.domains : [])) domains.add(String(domain).trim());
    for (const url of (Array.isArray(a.urls) ? a.urls : [])) urls.add(String(url).trim());
  }
  return { ips: [...ips].filter(Boolean).slice(0, 50), domains: [...domains].filter(Boolean).slice(0, 30), urls: [...urls].filter(Boolean).slice(0, 20) };
}

export default function ThreatMap({ cases, apiBase, onNavigate }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const indicators = useMemo(() => gatherIndicators(cases), [cases]);
  const signature = useMemo(() => JSON.stringify(indicators), [indicators]);

  useEffect(() => {
    const parsed = JSON.parse(signature);
    if (!parsed.ips.length && !parsed.domains.length && !parsed.urls.length) {
      setData({ markers: [], feed_status: {}, summary: { checked_indicators: 0, mapped_locations: 0 }, limitations: [] });
      setError("");
      return;
    }
    const controller = new AbortController();
    setLoading(true);
    setError("");
    fetch(`${apiBase}/api/intel/map-data`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(parsed), signal: controller.signal
    }).then(async response => {
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.detail || `Map lookup failed (${response.status})`);
      setData(payload);
    }).catch(err => { if (err.name !== "AbortError") setError(err.message || "Map lookup failed"); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [apiBase, signature]);

  const markers = data?.markers || [];
  const feeds = data?.feed_status || {};
  return <div className="matsya-map-wrap">
    <div className="matsya-map-status">
      <span>{loading ? "Checking indicators…" : `${markers.length} mapped public IP location${markers.length === 1 ? "" : "s"}`}</span>
      <span className={feeds.urlhaus === "connected" || feeds.abuseipdb === "connected" ? "feed-on" : "feed-off"}>
        {feeds.urlhaus === "connected" || feeds.abuseipdb === "connected" ? "Threat feed connected" : "Threat feed credentials not configured"}
      </span>
    </div>
    <MapContainer className="matsya-leaflet-map" center={[22.5, 79]} zoom={3} scrollWheelZoom={true} worldCopyJump={true}>
      <TileLayer attribution='&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noreferrer">OpenStreetMap</a>' url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" maxZoom={19}/>
      <FitMarkers markers={markers}/>
      {markers.map((m, i) => <CircleMarker key={`${m.ip}-${i}`} center={[m.latitude, m.longitude]} radius={m.threat_match ? 10 : 7} pathOptions={{ color: m.threat_match ? "#e11d48" : "#0284c7", fillColor: m.threat_match ? "#fb7185" : "#22d3ee", fillOpacity: 0.8, weight: 2 }}>
        <Popup><div className="matsya-map-popup"><b>{m.ip}</b><span>{[m.city, m.region, m.country].filter(Boolean).join(", ") || "Approximate location unavailable"}</span><span>Source: {m.geo_source || "GeoIP provider"}</span>{m.accuracy_radius_km ? <span>Accuracy radius: about {m.accuracy_radius_km} km</span> : null}<span>AbuseIPDB score: {m.abuse_confidence_score ?? "not available"}</span><span>URLhaus: {m.threat_match ? "matching malicious URL found" : (m.urlhaus_status || "not checked")}</span><small>IP geolocation is approximate and does not identify a person's exact location.</small></div></Popup>
      </CircleMarker>)}
    </MapContainer>
    {error && <div className="matsya-map-message error" role="alert">Map data could not load: {error}. Check FastAPI, API keys and GeoLite2 configuration.</div>}
    {!loading && !error && markers.length === 0 && <div className="matsya-map-message">{indicators.ips.length || indicators.domains.length || indicators.urls.length ? "No usable public IPs with GeoIP coordinates were returned. Private/reserved IPs and missing GeoIP records are excluded." : "Analyze an .eml file first. The map will use IPs/domains/URLs extracted from saved analysis results; no sample attack locations are fabricated."}<button className="secondary-button" type="button" onClick={() => onNavigate("upload")}>Upload evidence</button></div>}
    <div className="matsya-feed-footnote">Map tiles: OpenStreetMap. Threat checks: URLhaus and/or AbuseIPDB when configured. Markers are only plotted when a GeoIP provider returns coordinates; threat status is not inferred from location alone.</div>
  </div>;
}
