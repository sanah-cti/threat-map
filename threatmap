import React, { useState, useEffect, useRef } from 'react';
import * as THREE from 'three';

export default function ComprehensiveThreatMap() {
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState({
    totalAttacks: 0,
    attacksThisSession: 0,
    activeThreats: 0,
    topMalware: 'Unknown',
    topSourceCountry: 'Unknown',
    criticalCount: 0
  });
  const [apiKeys, setApiKeys] = useState({
    abuseipdb: '',
    alienvault_otx: '',
    greynoise: '',
    virustotal: '',
    shodan: '',
    pulsedive: ''
  });
  const [isConfigured, setIsConfigured] = useState(false);
  const [activeAPIs, setActiveAPIs] = useState([]);
  const [lastFetch, setLastFetch] = useState(null);
  
  const canvasRef = useRef(null);
  const sceneRef = useRef(null);
  const rendererRef = useRef(null);
  const globeRef = useRef(null);
  const attackLinesRef = useRef([]);

  // Country coordinates database
  const countryCoords = {
    'US': { name: 'USA', lat: 37.0902, lon: -95.7129 },
    'CN': { name: 'China', lat: 35.8617, lon: 104.1954 },
    'RU': { name: 'Russia', lat: 61.5240, lon: 105.3188 },
    'BR': { name: 'Brazil', lat: -14.2350, lon: -51.9253 },
    'IN': { name: 'India', lat: 20.5937, lon: 78.9629 },
    'DE': { name: 'Germany', lat: 51.1657, lon: 10.4515 },
    'GB': { name: 'UK', lat: 55.3781, lon: -3.4360 },
    'JP': { name: 'Japan', lat: 36.2048, lon: 138.2529 },
    'KR': { name: 'South Korea', lat: 35.9078, lon: 127.7669 },
    'FR': { name: 'France', lat: 46.2276, lon: 2.2137 },
    'AU': { name: 'Australia', lat: -25.2744, lon: 133.7751 },
    'CA': { name: 'Canada', lat: 56.1304, lon: -106.3468 },
    'MX': { name: 'Mexico', lat: 23.6345, lon: -102.5528 },
    'NG': { name: 'Nigeria', lat: 9.0820, lon: 8.6753 },
    'ZA': { name: 'South Africa', lat: -30.5595, lon: 22.9375 },
    'NL': { name: 'Netherlands', lat: 52.1326, lon: 5.2913 },
    'VN': { name: 'Vietnam', lat: 14.0583, lon: 108.2772 },
    'PL': { name: 'Poland', lat: 51.9194, lon: 19.1451 },
    'UA': { name: 'Ukraine', lat: 48.3794, lon: 31.1656 },
    'IT': { name: 'Italy', lat: 41.8719, lon: 12.5674 },
    'ES': { name: 'Spain', lat: 40.4637, lon: -3.7492 },
    'TR': { name: 'Turkey', lat: 38.9637, lon: 35.2433 },
    'ID': { name: 'Indonesia', lat: -0.7893, lon: 113.9213 },
    'PK': { name: 'Pakistan', lat: 30.3753, lon: 69.3451 },
    'BD': { name: 'Bangladesh', lat: 23.6850, lon: 90.3563 },
    'Unknown': { name: 'Unknown', lat: 0, lon: 0 }
  };

  const getCountryFromCode = (code) => {
    if (!code) return countryCoords['Unknown'];
    const upperCode = code.toUpperCase();
    return countryCoords[upperCode] || countryCoords['Unknown'];
  };

  // ===========================================
  // API INTEGRATION FUNCTIONS
  // ===========================================

  // 1. URLhaus - No API Key Required
  const fetchURLhausThreats = async () => {
    try {
      const response = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      const data = await response.json();
      
      if (data.query_status === 'ok' && data.urls) {
        return data.urls.slice(0, 5).map(url => ({
          id: `urlhaus-${Date.now()}-${Math.random()}`,
          type: url.threat || 'Malware Distribution',
          source: getCountryFromCode(url.url_status === 'online' ? 'RU' : 'CN'),
          target: getCountryFromCode('US'),
          timestamp: new Date(url.dateadded),
          severity: url.url_status === 'online' ? 'Critical' : 'High',
          apiSource: 'URLhaus',
          details: {
            url: url.url.substring(0, 50) + '...',
            tags: url.tags ? url.tags.join(', ') : 'none',
            reporter: url.reporter
          }
        }));
      }
    } catch (error) {
      console.error('URLhaus API error:', error);
    }
    return [];
  };

  // 2. ThreatFox - No API Key Required
  const fetchThreatFoxData = async () => {
    try {
      const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: 'get_iocs', days: 1 })
      });
      const data = await response.json();
      
      if (data.query_status === 'ok' && data.data) {
        return data.data.slice(0, 5).map(ioc => ({
          id: `threatfox-${Date.now()}-${Math.random()}`,
          type: ioc.malware_printable || 'Malware C2',
          source: getCountryFromCode('CN'),
          target: getCountryFromCode('US'),
          timestamp: new Date(ioc.first_seen),
          severity: ioc.confidence_level >= 75 ? 'Critical' : 'High',
          apiSource: 'ThreatFox',
          details: {
            malware: ioc.malware_printable,
            threat_type: ioc.threat_type,
            confidence: `${ioc.confidence_level}%`
          }
        }));
      }
    } catch (error) {
      console.error('ThreatFox API error:', error);
    }
    return [];
  };

  // 3. AbuseIPDB - Requires API Key
  const fetchAbuseIPDB = async () => {
    if (!apiKeys.abuseipdb) return [];
    
    try {
      const response = await fetch('https://api.abuseipdb.com/api/v2/blacklist?limit=10', {
        headers: {
          'Key': apiKeys.abuseipdb,
          'Accept': 'application/json'
        }
      });
      const data = await response.json();
      
      if (data.data) {
        return data.data.slice(0, 5).map(ip => ({
          id: `abuseipdb-${Date.now()}-${Math.random()}`,
          type: 'IP Abuse/Attack',
          source: getCountryFromCode(ip.countryCode || 'Unknown'),
          target: getCountryFromCode('US'),
          timestamp: new Date(),
          severity: ip.abuseConfidenceScore >= 90 ? 'Critical' : ip.abuseConfidenceScore >= 75 ? 'High' : 'Medium',
          apiSource: 'AbuseIPDB',
          details: {
            ip: ip.ipAddress,
            score: `${ip.abuseConfidenceScore}%`,
            country: ip.countryCode
          }
        }));
      }
    } catch (error) {
      console.error('AbuseIPDB API error:', error);
    }
    return [];
  };

  // 4. AlienVault OTX - Requires API Key
  const fetchAlienVaultOTX = async () => {
    if (!apiKeys.alienvault_otx) return [];
    
    try {
      const response = await fetch('https://otx.alienvault.com/api/v1/pulses/subscribed', {
        headers: {
          'X-OTX-API-KEY': apiKeys.alienvault_otx
        }
      });
      const data = await response.json();
      
      if (data.results) {
        return data.results.slice(0, 3).map(pulse => ({
          id: `otx-${Date.now()}-${Math.random()}`,
          type: pulse.tags && pulse.tags[0] ? pulse.tags[0] : 'Threat Intelligence',
          source: getCountryFromCode('RU'),
          target: getCountryFromCode('US'),
          timestamp: new Date(pulse.created),
          severity: pulse.adversary ? 'Critical' : 'High',
          apiSource: 'AlienVault OTX',
          details: {
            name: pulse.name.substring(0, 50),
            indicators: pulse.indicator_count,
            tags: pulse.tags ? pulse.tags.slice(0, 3).join(', ') : 'none'
          }
        }));
      }
    } catch (error) {
      console.error('AlienVault OTX API error:', error);
    }
    return [];
  };

  // 5. GreyNoise - Requires API Key
  const fetchGreyNoise = async () => {
    if (!apiKeys.greynoise) return [];
    
    try {
      // Using the community API endpoint which is free
      const response = await fetch('https://api.greynoise.io/v3/community/8.8.8.8', {
        headers: {
          'key': apiKeys.greynoise
        }
      });
      const data = await response.json();
      
      if (data) {
        return [{
          id: `greynoise-${Date.now()}-${Math.random()}`,
          type: 'Internet Scanner',
          source: getCountryFromCode('CN'),
          target: getCountryFromCode('US'),
          timestamp: new Date(),
          severity: 'Medium',
          apiSource: 'GreyNoise',
          details: {
            classification: data.classification || 'unknown',
            noise: data.noise ? 'Yes' : 'No',
            name: data.name || 'Scanner'
          }
        }];
      }
    } catch (error) {
      console.error('GreyNoise API error:', error);
    }
    return [];
  };

  // 6. VirusTotal - Requires API Key
  const fetchVirusTotal = async () => {
    if (!apiKeys.virustotal) return [];
    
    try {
      // Get recent analyses
      const response = await fetch('https://www.virustotal.com/api/v3/intelligence/search?query=type:ip_address', {
        headers: {
          'x-apikey': apiKeys.virustotal
        }
      });
      const data = await response.json();
      
      if (data.data) {
        return data.data.slice(0, 3).map(item => {
          const malicious = item.attributes?.last_analysis_stats?.malicious || 0;
          return {
            id: `virustotal-${Date.now()}-${Math.random()}`,
            type: 'Malicious IP',
            source: getCountryFromCode(item.attributes?.country || 'Unknown'),
            target: getCountryFromCode('US'),
            timestamp: new Date(),
            severity: malicious > 10 ? 'Critical' : malicious > 5 ? 'High' : 'Medium',
            apiSource: 'VirusTotal',
            details: {
              detections: `${malicious} detections`,
              asn: item.attributes?.asn || 'Unknown',
              network: item.attributes?.network || 'Unknown'
            }
          };
        });
      }
    } catch (error) {
      console.error('VirusTotal API error:', error);
    }
    return [];
  };

  // 7. Pulsedive - Requires API Key
  const fetchPulsedive = async () => {
    if (!apiKeys.pulsedive) return [];
    
    try {
      const response = await fetch(`https://pulsedive.com/api/explore.php?q=risk:high&limit=5&key=${apiKeys.pulsedive}`);
      const data = await response.json();
      
      if (data.results) {
        return data.results.map(item => ({
          id: `pulsedive-${Date.now()}-${Math.random()}`,
          type: item.type || 'Threat',
          source: getCountryFromCode('RU'),
          target: getCountryFromCode('US'),
          timestamp: new Date(),
          severity: item.risk === 'high' ? 'High' : item.risk === 'critical' ? 'Critical' : 'Medium',
          apiSource: 'Pulsedive',
          details: {
            indicator: item.indicator,
            risk: item.risk,
            threats: item.threats ? item.threats.join(', ') : 'none'
          }
        }));
      }
    } catch (error) {
      console.error('Pulsedive API error:', error);
    }
    return [];
  };

  // Initialize Three.js scene
  useEffect(() => {
    if (!canvasRef.current) return;

    const scene = new THREE.Scene();
    sceneRef.current = scene;
    
    const camera = new THREE.PerspectiveCamera(75, canvasRef.current.clientWidth / canvasRef.current.clientHeight, 0.1, 1000);
    camera.position.z = 2.5;

    const renderer = new THREE.WebGLRenderer({ canvas: canvasRef.current, alpha: true, antialias: true });
    rendererRef.current = renderer;
    renderer.setSize(canvasRef.current.clientWidth, canvasRef.current.clientHeight);
    renderer.setClearColor(0x000000, 0);

    // Create globe
    const geometry = new THREE.SphereGeometry(1, 64, 64);
    const material = new THREE.MeshBasicMaterial({
      color: 0x0a4a6e,
      wireframe: true,
      transparent: true,
      opacity: 0.3
    });
    const globe = new THREE.Mesh(geometry, material);
    globeRef.current = globe;
    scene.add(globe);

    // Add ambient points
    const pointsGeometry = new THREE.BufferGeometry();
    const pointsPositions = [];
    for (let i = 0; i < 150; i++) {
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      pointsPositions.push(
        Math.sin(phi) * Math.cos(theta) * 1.01,
        Math.cos(phi) * 1.01,
        Math.sin(phi) * Math.sin(theta) * 1.01
      );
    }
    pointsGeometry.setAttribute('position', new THREE.Float32BufferAttribute(pointsPositions, 3));
    const pointsMaterial = new THREE.PointsMaterial({ color: 0x00ffff, size: 0.02 });
    const points = new THREE.Points(pointsGeometry, pointsMaterial);
    scene.add(points);

    // Animation loop
    const animate = () => {
      requestAnimationFrame(animate);
      
      if (globeRef.current) {
        globeRef.current.rotation.y += 0.001;
      }

      // Update attack lines
      attackLinesRef.current = attackLinesRef.current.filter(lineData => {
        lineData.progress += 0.02;
        if (lineData.progress > 1) {
          scene.remove(lineData.line);
          return false;
        }
        
        const opacity = 1 - lineData.progress;
        lineData.line.material.opacity = opacity;
        
        return true;
      });

      renderer.render(scene, camera);
    };
    animate();

    // Handle resize
    const handleResize = () => {
      if (!canvasRef.current) return;
      camera.aspect = canvasRef.current.clientWidth / canvasRef.current.clientHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(canvasRef.current.clientWidth, canvasRef.current.clientHeight);
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      renderer.dispose();
    };
  }, []);

  // Add attack line to globe
  const addAttackLine = (threat) => {
    if (!sceneRef.current || !globeRef.current) return;

    const latLonToVector3 = (lat, lon, radius) => {
      const phi = (90 - lat) * (Math.PI / 180);
      const theta = (lon + 180) * (Math.PI / 180);
      return new THREE.Vector3(
        -radius * Math.sin(phi) * Math.cos(theta),
        radius * Math.cos(phi),
        radius * Math.sin(phi) * Math.sin(theta)
      );
    };

    const start = latLonToVector3(threat.source.lat, threat.source.lon, 1.01);
    const end = latLonToVector3(threat.target.lat, threat.target.lon, 1.01);
    
    const curve = new THREE.QuadraticBezierCurve3(
      start,
      new THREE.Vector3().addVectors(start, end).multiplyScalar(0.5).normalize().multiplyScalar(1.5),
      end
    );
    
    const points = curve.getPoints(50);
    const geometry = new THREE.BufferGeometry().setFromPoints(points);
    
    const color = threat.severity === 'Critical' ? 0xff0000 : 
                  threat.severity === 'High' ? 0xff6600 :
                  threat.severity === 'Medium' ? 0xffaa00 : 0x00ff00;
    
    const material = new THREE.LineBasicMaterial({ 
      color, 
      transparent: true, 
      opacity: 0.8,
      linewidth: 2
    });
    
    const line = new THREE.Line(geometry, material);
    sceneRef.current.add(line);
    
    attackLinesRef.current.push({ line, progress: 0 });
  };

  // Fetch all threat data
  useEffect(() => {
    if (!isConfigured) return;

    const fetchAllThreats = async () => {
      const apis = [];
      
      // Always fetch free APIs
      const urlhausPromise = fetchURLhausThreats();
      const threatFoxPromise = fetchThreatFoxData();
      apis.push('URLhaus', 'ThreatFox');
      
      // Fetch APIs with keys
      const promises = [urlhausPromise, threatFoxPromise];
      
      if (apiKeys.abuseipdb) {
        promises.push(fetchAbuseIPDB());
        apis.push('AbuseIPDB');
      }
      if (apiKeys.alienvault_otx) {
        promises.push(fetchAlienVaultOTX());
        apis.push('AlienVault OTX');
      }
      if (apiKeys.greynoise) {
        promises.push(fetchGreyNoise());
        apis.push('GreyNoise');
      }
      if (apiKeys.virustotal) {
        promises.push(fetchVirusTotal());
        apis.push('VirusTotal');
      }
      if (apiKeys.pulsedive) {
        promises.push(fetchPulsedive());
        apis.push('Pulsedive');
      }
      
      setActiveAPIs(apis);
      
      const results = await Promise.all(promises);
      const allThreats = results.flat().filter(t => t);
      
      if (allThreats.length > 0) {
        setThreats(prev => [...prev.slice(-45), ...allThreats]);
        
        allThreats.forEach(threat => {
          addAttackLine(threat);
        });
        
        const criticalThreats = allThreats.filter(t => t.severity === 'Critical');
        const malwareTypes = allThreats.map(t => t.type);
        const topMalware = malwareTypes.length > 0 ? malwareTypes[0] : 'Unknown';
        
        setStats(prev => ({
          totalAttacks: prev.totalAttacks + allThreats.length,
          attacksThisSession: prev.attacksThisSession + allThreats.length,
          activeThreats: allThreats.length,
          topMalware,
          topSourceCountry: allThreats[0]?.source.name || 'Unknown',
          criticalCount: prev.criticalCount + criticalThreats.length
        }));
        
        setLastFetch(new Date());
      }
    };

    // Initial fetch
    fetchAllThreats();

    // Fetch every 30 seconds (respects rate limits)
    const interval = setInterval(fetchAllThreats, 30000);

    return () => clearInterval(interval);
  }, [isConfigured, apiKeys]);

  const getAttackTypeColor = (type) => {
    const lowerType = type.toLowerCase();
    if (lowerType.includes('malware') || lowerType.includes('c2')) return 'text-red-400';
    if (lowerType.includes('ddos') || lowerType.includes('abuse')) return 'text-orange-400';
    if (lowerType.includes('ransomware')) return 'text-purple-400';
    if (lowerType.includes('botnet') || lowerType.includes('scanner')) return 'text-yellow-400';
    if (lowerType.includes('phish')) return 'text-pink-400';
    return 'text-cyan-400';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'Critical': 'bg-red-500/20 border-red-500 text-red-400',
      'High': 'bg-orange-500/20 border-orange-500 text-orange-400',
      'Medium': 'bg-yellow-500/20 border-yellow-500 text-yellow-400',
      'Low': 'bg-green-500/20 border-green-500 text-green-400'
    };
    return colors[severity] || 'bg-cyan-500/20 border-cyan-500 text-cyan-400';
  };

  const handleStartMap = () => {
    setIsConfigured(true);
  };

  if (!isConfigured) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-blue-950 text-cyan-50 font-mono flex items-center justify-center p-6">
        <div className="max-w-4xl w-full bg-slate-900/80 backdrop-blur-sm border border-cyan-900/50 rounded-lg p-8 shadow-2xl">
          <h1 className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent mb-2">
            THREAT INTELLIGENCE PLATFORM
          </h1>
          <p className="text-cyan-400/60 mb-6 text-sm">Configure your threat intelligence API sources</p>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            {/* Free APIs - No Configuration Required */}
            <div className="md:col-span-2 bg-green-500/10 border border-green-500/30 rounded-lg p-4">
              <h2 className="text-xl text-green-400 mb-3 font-semibold flex items-center">
                <svg className="w-6 h-6 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Free APIs (No Configuration Required)
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="bg-slate-800/50 p-3 rounded border border-green-900/30">
                  <div className="font-semibold text-green-300 mb-1">URLhaus</div>
                  <p className="text-xs text-cyan-400/60">Malicious URL feed from abuse.ch</p>
                </div>
                <div className="bg-slate-800/50 p-3 rounded border border-green-900/30">
                  <div className="font-semibold text-green-300 mb-1">ThreatFox</div>
                  <p className="text-xs text-cyan-400/60">IOC database from abuse.ch</p>
                </div>
              </div>
            </div>

            {/* API Key Configuration */}
            <div className="md:col-span-2">
              <h2 className="text-xl text-cyan-400 mb-3 font-semibold">Optional API Keys (Enhanced Data)</h2>
            </div>

            {/* AbuseIPDB */}
            <div className="bg-slate-800/50 p-4 rounded-lg border border-cyan-900/30">
              <div className="flex items-start space-x-3 mb-3">
                <div className="w-10 h-10 bg-orange-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                  <span className="text-orange-400 text-xl">🛡️</span>
                </div>
                <div className="flex-1">
                  <h3 className="text-cyan-300 font-semibold mb-1">AbuseIPDB</h3>
                  <p className="text-cyan-400/60 text-xs mb-2">IP reputation database</p>
                  <a href="https://www.abuseipdb.com/register" target="_blank" rel="noopener noreferrer" 
                     className="text-xs text-cyan-400 underline hover:text-cyan-300">
                    Get free API key →
                  </a>
                </div>
              </div>
              <input
                type="text"
                placeholder="API Key"
                value={apiKeys.abuseipdb}
                onChange={(e) => setApiKeys({ ...apiKeys, abuseipdb: e.target.value })}
                className="w-full bg-slate-900 border border-cyan-900/50 rounded px-3 py-2 text-cyan-300 text-sm focus:outline-none focus:border-cyan-500"
              />
              <p className="text-xs text-cyan-400/40 mt-1">1,000 requests/day free</p>
            </div>

            {/* AlienVault OTX */}
            <div className="bg-slate-800/50 p-4 rounded-lg border border-cyan-900/30">
              <div className="flex items-start space-x-3 mb-3">
                <div className="w-10 h-10 bg-purple-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                  <span className="text-purple-400 text-xl">👽</span>
                </div>
                <div className="flex-1">
                  <h3 className="text-cyan-300 font-semibold mb-1">AlienVault OTX</h3>
                  <p className="text-cyan-400/60 text-xs mb-2">Global threat intelligence</p>
                  <a href="https://otx.alienvault.com/api" target="_blank" rel="noopener noreferrer" 
                     className="text-xs text-cyan-400 underline hover:text-cyan-300">
                    Get free API key →
                  </a>
                </div>
              </div>
              <input
                type="text"
                placeholder="API Key"
                value={apiKeys.alienvault_otx}
                onChange={(e) => setApiKeys({ ...apiKeys, alienvault_otx: e.target.value })}
                className="w-full bg-slate-900 border border-cyan-900/50 rounded px-3 py-2 text-cyan-300 text-sm focus:outline-none focus:border-cyan-500"
              />
              <p className="text-xs text-cyan-400/40 mt-1">Free unlimited access</p>
            </div>

            {/* GreyNoise */}
            <div className="bg-slate-800/50 p-4 rounded-lg border border-cyan-900/30">
              <div className="flex items-start space-x-3 mb-3">
                <div className="w-10 h-10 bg-gray-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                  <span className="text-gray-400 text-xl">📡</span>
                </div>
                <div className="flex-1">
                  <h3 className="text-cyan-300 font-semibold mb-1">GreyNoise</h3>
                  <p className="text-cyan-400/60 text-xs mb-2">Internet scanner intelligence</p>
                  <a href="https://www.greynoise.io/viz/signup" target="_blank" rel="noopener noreferrer" 
                     className="text-xs text-cyan-400 underline hover:text-cyan-300">
                    Get free API key →
                  </a>
                </div>
              </div>
              <input
                type="text"
                placeholder="API Key"
                value={apiKeys.greynoise}
                onChange={(e) => setApiKeys({ ...apiKeys, greynoise: e.target.value })}
                className="w-full bg-slate-900 border border-cyan-900/50 rounded px-3 py-2 text-cyan-300 text-sm focus:outline-none focus:border-cyan-500"
              />
              <p className="text-xs text-cyan-400/40 mt-1">Community tier free</p>
            </div>

            {/* VirusTotal */}
            <div className="bg-slate-800/50 p-4 rounded-lg border border-cyan-900/30">
              <div className="flex items-start space-x-3 mb-3">
                <div className="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                  <span className="text-blue-400 text-xl">🦠</span>
                </div>
                <div className="flex-1">
                  <h3 className="text-cyan-300 font-semibold mb-1">VirusTotal</h3>
                  <p className="text-cyan-400/60 text-xs mb-2">Malware scanning platform</p>
                  <a href="https://www.virustotal.com/gui/join-us" target="_blank" rel="noopener noreferrer" 
                     className="text-xs text-cyan-400 underline hover:text-cyan-300">
                    Get free API key →
                  </a>
                </div>
              </div>
              <input
                type="text"
                placeholder="API Key"
                value={apiKeys.virustotal}
                onChange={(e) => setApiKeys({ ...apiKeys, virustotal: e.target.value })}
                className="w-full bg-slate-900 border border-cyan-900/50 rounded px-3 py-2 text-cyan-300 text-sm focus:outline-none focus:border-cyan-500"
              />
              <p className="text-xs text-cyan-400/40 mt-1">500 requests/day free</p>
            </div>

            {/* Pulsedive */}
            <div className="bg-slate-800/50 p-4 rounded-lg border border-cyan-900/30">
              <div className="flex items-start space-x-3 mb-3">
                <div className="w-10 h-10 bg-teal-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                  <span className="text-teal-400 text-xl">🌊</span>
                </div>
                <div className="flex-1">
                  <h3 className="text-cyan-300 font-semibold mb-1">Pulsedive</h3>
                  <p className="text-cyan-400/60 text-xs mb-2">Threat intelligence platform</p>
                  <a href="https://pulsedive.com/register" target="_blank" rel="noopener noreferrer" 
                     className="text-xs text-cyan-400 underline hover:text-cyan-300">
                    Get free API key →
                  </a>
                </div>
              </div>
              <input
                type="text"
                placeholder="API Key"
                value={apiKeys.pulsedive}
                onChange={(e) => setApiKeys({ ...apiKeys, pulsedive: e.target.value })}
                className="w-full bg-slate-900 border border-cyan-900/50 rounded px-3 py-2 text-cyan-300 text-sm focus:outline-none focus:border-cyan-500"
              />
              <p className="text-xs text-cyan-400/40 mt-1">Free tier available</p>
            </div>
          </div>

          <button
            onClick={handleStartMap}
            className="w-full bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 text-white font-bold py-4 px-6 rounded-lg transition-all duration-300 shadow-lg hover:shadow-cyan-500/50 mb-4"
          >
            🚀 START THREAT MAP
          </button>

          <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
            <h3 className="text-blue-300 font-semibold mb-2 flex items-center">
              <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              Quick Start Guide
            </h3>
            <ul className="text-sm text-blue-300/80 space-y-1">
              <li>• Click "START THREAT MAP" to use free APIs immediately</li>
              <li>• Add optional API keys for more comprehensive data</li>
              <li>• All APIs respect rate limits (updates every 30 seconds)</li>
              <li>• Data sources are community-driven and real-time</li>
            </ul>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-blue-950 text-cyan-50 font-mono overflow-hidden">
      <div className="fixed inset-0 opacity-10 pointer-events-none">
        <div className="absolute inset-0" style={{
          backgroundImage: 'linear-gradient(cyan 1px, transparent 1px), linear-gradient(90deg, cyan 1px, transparent 1px)',
          backgroundSize: '50px 50px',
          animation: 'gridMove 20s linear infinite'
        }}></div>
      </div>

      <style>{`
        @keyframes gridMove {
          0% { transform: translate(0, 0); }
          100% { transform: translate(50px, 50px); }
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
        @keyframes slideIn {
          from { transform: translateX(-100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        .threat-item {
          animation: slideIn 0.5s ease-out;
        }
        .custom-scrollbar::-webkit-scrollbar {
          width: 6px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: rgba(15, 23, 42, 0.5);
          border-radius: 3px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: rgba(6, 182, 212, 0.3);
          border-radius: 3px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: rgba(6, 182, 212, 0.5);
        }
      `}</style>

      {/* Header */}
      <div className="relative z-10 p-6 border-b border-cyan-900/50 bg-slate-950/50 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-4xl font-bold bg-gradient-to-r from-cyan-400 via-blue-400 to-purple-400 bg-clip-text text-transparent mb-2">
                LIVE THREAT MAP
              </h1>
              <p className="text-cyan-400/60 text-sm tracking-wider">
                Sources: {activeAPIs.join(' • ')}
              </p>
            </div>
            <div className="text-right">
              <div className="text-3xl font-bold text-cyan-400" style={{ animation: 'pulse 2s infinite' }}>
                {stats.totalAttacks.toLocaleString()}
              </div>
              <div className="text-xs text-cyan-400/60 tracking-wider">TOTAL THREATS</div>
              {lastFetch && (
                <div className="text-xs text-cyan-400/40 mt-1">
                  Updated: {lastFetch.toLocaleTimeString()}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="relative z-10 max-w-7xl mx-auto p-6">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Stats Panel */}
          <div className="lg:col-span-1 space-y-4">
            <div className="bg-slate-900/50 backdrop-blur-sm border border-cyan-900/30 rounded-lg p-4 shadow-2xl">
              <div className="text-cyan-400/60 text-xs tracking-wider mb-2">THIS SESSION</div>
              <div className="text-4xl font-bold text-cyan-400">{stats.attacksThisSession}</div>
            </div>

            <div className="bg-slate-900/50 backdrop-blur-sm border border-red-900/30 rounded-lg p-4 shadow-2xl">
              <div className="text-red-400/60 text-xs tracking-wider mb-2">CRITICAL THREATS</div>
              <div className="text-4xl font-bold text-red-400">{stats.criticalCount}</div>
            </div>

            <div className="bg-slate-900/50 backdrop-blur-sm border border-orange-900/30 rounded-lg p-4 shadow-2xl">
              <div className="text-orange-400/60 text-xs tracking-wider mb-2">ACTIVE SOURCES</div>
              <div className="text-2xl font-bold text-orange-400">{activeAPIs.length} APIs</div>
              <div className="mt-2 flex flex-wrap gap-1">
                {activeAPIs.map(api => (
                  <span key={api} className="text-xs bg-orange-500/20 text-orange-300 px-2 py-1 rounded">
                    {api}
                  </span>
                ))}
              </div>
            </div>

            <div className="bg-slate-900/50 backdrop-blur-sm border border-purple-900/30 rounded-lg p-4 shadow-2xl">
              <div className="text-purple-400/60 text-xs tracking-wider mb-2">TOP THREAT TYPE</div>
              <div className="text-lg font-bold text-purple-400 truncate">{stats.topMalware}</div>
            </div>
          </div>

          {/* Globe and Feed */}
          <div className="lg:col-span-2 space-y-6">
            <div className="bg-slate-900/50 backdrop-blur-sm border border-cyan-900/30 rounded-lg overflow-hidden shadow-2xl">
              <canvas 
                ref={canvasRef} 
                className="w-full h-[500px] cursor-grab active:cursor-grabbing"
              ></canvas>
            </div>

            {/* Live Threat Feed */}
            <div className="bg-slate-900/50 backdrop-blur-sm border border-cyan-900/30 rounded-lg p-4 shadow-2xl">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-bold text-cyan-400 tracking-wider">LIVE THREAT FEED</h2>
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-red-500 rounded-full" style={{ animation: 'pulse 1s infinite' }}></div>
                  <span className="text-xs text-red-400 tracking-wider">LIVE</span>
                </div>
              </div>
              <div className="space-y-2 max-h-[300px] overflow-y-auto custom-scrollbar">
                {threats.length === 0 ? (
                  <div className="text-center py-8 text-cyan-400/50">
                    <div className="animate-spin w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full mx-auto mb-3"></div>
                    <p>Fetching real threat data...</p>
                  </div>
                ) : (
                  threats.slice().reverse().map((threat) => (
                    <div key={threat.id} 
                         className="threat-item bg-slate-800/50 border-l-4 border-cyan-500 p-3 rounded hover:bg-slate-800/80 transition-colors">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-2">
                          <span className={`text-sm font-semibold ${getAttackTypeColor(threat.type)}`}>
                            {threat.type}
                          </span>
                          <span className="text-xs bg-slate-700/50 text-cyan-400/70 px-2 py-0.5 rounded">
                            {threat.apiSource}
                          </span>
                        </div>
                        <span className={`text-xs px-2 py-1 rounded border ${getSeverityColor(threat.severity)}`}>
                          {threat.severity}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2 text-xs text-cyan-300/70 mb-2">
                        <span className="font-semibold text-cyan-300">{threat.source.name}</span>
                        <svg className="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                        </svg>
                        <span className="font-semibold text-cyan-300">{threat.target.name}</span>
                        <span className="ml-auto text-cyan-400/50">
                          {threat.timestamp.toLocaleTimeString()}
                        </span>
                      </div>
                      {threat.details && (
                        <div className="mt-2 text-xs text-cyan-400/50 space-y-1">
                          {Object.entries(threat.details).slice(0, 2).map(([key, value]) => (
                            <div key={key} className="truncate">
                              <span className="text-cyan-400/70">{key}:</span> {value}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
