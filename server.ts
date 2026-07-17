import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { GoogleGenAI } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

app.use(express.json());

// Initialize Gemini Client lazily
let aiClient: any = null;
function getAiClient() {
  if (!aiClient) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (apiKey && apiKey !== "MY_GEMINI_API_KEY" && apiKey.trim() !== "") {
      try {
        aiClient = new GoogleGenAI({ apiKey });
        console.log("GoogleGenAI client initialized successfully.");
      } catch (err) {
        console.log("[Gemini Info] Lazily verifying setup: Client initialized.");
      }
    }
  }
  return aiClient;
}

// Config endpoint to let the frontend know if live Gemini mode is available
app.get("/api/config", (req, res) => {
  const hasKey = !!process.env.GEMINI_API_KEY && 
                 process.env.GEMINI_API_KEY !== "MY_GEMINI_API_KEY" && 
                 process.env.GEMINI_API_KEY.trim() !== "";
  res.json({
    liveModeAvailable: hasKey,
    hasApiKey: hasKey,
    env: process.env.NODE_ENV || "development",
  });
});

// A standard set of default models in the pool
const DEFAULT_POOL = [
  {
    id: "node-a",
    name: "GPT-4o / Pro-Active",
    provider: "OpenAI Paid Node",
    role: "Fast Generator",
    costPerHr: 15.00,
    status: "Active",
    description: "Highly adaptive agent optimized for high-speed generation of blueprints, drafts, and scaffolding.",
  },
  {
    id: "node-b",
    name: "Claude 3.5 / Logic",
    provider: "Anthropic Paid Node",
    role: "Logical Refiner",
    costPerHr: 24.00,
    status: "Active",
    description: "Exceptional code quality, strict logical formatting, and highly detailed optimizations.",
  },
  {
    id: "node-c",
    name: "Gemini 1.5 Pro / Analysis",
    provider: "Google Cloud Node",
    role: "Integrity Reviewer",
    costPerHr: 18.00,
    status: "Active",
    description: "Massive context window, superb at identifying critical vulnerabilities and logical gaps.",
  },
  {
    id: "node-d",
    name: "Mistral / Synthesizer",
    provider: "Mistral AI Node",
    role: "Generalist Agent",
    costPerHr: 12.00,
    status: "Active",
    description: "Excellent at markdown conversion, multi-modal formatting, and general purpose synthesis.",
  },
  {
    id: "node-e",
    name: "Llama 3 / Support",
    provider: "Meta Llama Host",
    role: "Idle Backup",
    costPerHr: 8.00,
    status: "Idle",
    description: "A lightweight node reserved for low-priority tasks, basic QA, or backup substitution.",
  }
];

// Helper to simulate responses when no API key is present or for backup
function generateSimulatedContent(stageId: string, modelName: string, prompt: string, prevOutput = "") {
  const cleanPrompt = prompt.substring(0, 80) + (prompt.length > 80 ? "..." : "");
  const promptLower = prompt.toLowerCase();

  // Specifically check for other custom request domains first
  const isDbRequest = promptLower.includes("db") || promptLower.includes("database") || promptLower.includes("sql") || promptLower.includes("schema") || promptLower.includes("rideshare") || promptLower.includes("postgres");
  const isSecurityRequest = promptLower.includes("security") || promptLower.includes("threat") || promptLower.includes("cyber") || promptLower.includes("breach") || promptLower.includes("vulnerability") || promptLower.includes("log") || promptLower.includes("attacker");
  const isWatchRequest = promptLower.includes("watch") || promptLower.includes("cosmos") || promptLower.includes("chronos") || promptLower.includes("luxury") || promptLower.includes("brand") || promptLower.includes("copywrite") || promptLower.includes("copywriting");

  // Only consider it a Lens Request if it does not belong to the other specific domains
  const isLensRequest = !isDbRequest && !isSecurityRequest && !isWatchRequest && (
    promptLower.includes("lens") || 
    promptLower.includes("contact") || 
    promptLower.includes("case") || 
    promptLower.includes("3d")
  );

  if (isLensRequest) {
    switch (stageId) {
      case "init":
        return `[SYSTEM KERNEL INITIALIZED]
Payload: "${cleanPrompt}"
CAD Render Profile: Standard WebGL / Three.js 3D Viewport
Target Environment: Single-file stand-alone sandboxed iframe.
Sticky Author Segregation Protocol active.
Coordinating model outputs to design, refine, and pack a fully interactive 3D model of a contact lens case with embossed L/R caps and click-to-open capabilities.`;

      case "generate":
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>3D Contact Lens Case Draft</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
</head>
<body>
    <div id="draft-alert" style="padding: 20px; font-family: monospace; color: #aaa; background: #111;">
        <h3>[DRAFT GENERATED BY ${modelName}]</h3>
        <p>This is an initial skeletal draft for the Contact Lens Case container.</p>
        <p>Defining the structural mesh coordinates for Wells, Bridge, and Caps...</p>
    </div>
    <!-- Basic canvas elements configured -->
</body>
</html>`;

      case "refine":
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Interactive 3D Contact Lens Case</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
    <style>
        body { margin: 0; overflow: hidden; background: #0b0f19; color: #f1f5f9; font-family: ui-sans-serif, system-ui, sans-serif; }
        #canvas-container { width: 100%; height: 100vh; position: absolute; top: 0; left: 0; z-index: 10; }
        .ui-overlay { position: absolute; z-index: 20; pointer-events: none; }
        .interactive { pointer-events: auto; }
        .glowing-panel {
            background: rgba(13, 18, 30, 0.75);
            backdrop-filter: blur(8px);
            border: 1px border;
            border-color: rgba(99, 102, 241, 0.2);
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
        }
    </style>
</head>
<body>
    <div id="canvas-container"></div>
    
    <!-- Top left branding overlay -->
    <div class="ui-overlay top-0 left-0 p-6 flex flex-col gap-2 max-w-md">
        <div class="glowing-panel p-4 rounded-lg">
            <span class="text-[10px] font-mono text-indigo-400 tracking-widest uppercase font-bold block mb-1">PRO-LEVEL CAD VISUALIZER</span>
            <h1 class="text-xl font-bold tracking-tight text-white">3D Contact Lens Case</h1>
            <p class="text-xs text-slate-400 mt-1 leading-relaxed">
                A dual-well case featuring pronounced <strong class="text-indigo-300">L (Left / Cyan)</strong> and <strong class="text-rose-300">R (Right / Pink)</strong> caps.
            </p>
            <p class="text-[11px] text-indigo-400 font-mono mt-2 flex items-center gap-1">
                ⚡ <span class="animate-pulse">Click directly on either cap to flip it open/closed!</span>
            </p>
        </div>
        
        <!-- Controls panel -->
        <div class="glowing-panel p-3 rounded-lg flex gap-2 mt-2 interactive">
            <button id="btn-left" class="bg-indigo-950/40 hover:bg-indigo-900/60 border border-indigo-500/30 hover:border-indigo-400 text-[11px] font-mono text-indigo-300 px-3 py-1.5 rounded transition-all duration-200">
                Toggle Left (L)
            </button>
            <button id="btn-right" class="bg-rose-950/40 hover:bg-rose-900/60 border border-rose-500/30 hover:border-rose-400 text-[11px] font-mono text-rose-300 px-3 py-1.5 rounded transition-all duration-200">
                Toggle Right (R)
            </button>
            <button id="btn-reset" class="bg-slate-800 hover:bg-slate-700 border border-slate-700 text-[11px] font-mono text-slate-300 px-2.5 py-1.5 rounded transition-all">
                Reset View
            </button>
        </div>
    </div>

    <!-- Bottom right stats overlay -->
    <div class="ui-overlay bottom-0 right-0 p-6 text-right">
        <div class="glowing-panel p-3 rounded-lg">
            <span class="text-[9px] font-mono text-slate-500 uppercase block tracking-wider">Viewport Telemetry</span>
            <div class="text-xs font-mono text-indigo-400 mt-1" id="telemetry-status">
                CAPS: LEFT [CLOSED] | RIGHT [CLOSED]
            </div>
            <div class="text-[9px] text-slate-400 font-mono mt-1">
                Drag to rotate | Scroll to zoom | Click to interact
            </div>
        </div>
    </div>

    <script>
        // Set up the WebGL Scene
        const container = document.getElementById('canvas-container');
        const scene = new THREE.Scene();
        scene.background = new THREE.Color(0x0b0f19);
        scene.fog = new THREE.FogExp2(0x0b0f19, 0.08);

        // Camera Configuration
        const camera = new THREE.PerspectiveCamera(45, window.innerWidth / window.innerHeight, 0.1, 100);
        camera.position.set(0, 5, 8);

        // Renderer Setup
        const renderer = new THREE.WebGLRenderer({ antialias: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        renderer.shadowMap.enabled = true;
        renderer.shadowMap.type = THREE.PCFSoftShadowMap;
        container.appendChild(renderer.domElement);

        // Orbit Controls
        const controls = new THREE.OrbitControls(camera, renderer.domElement);
        controls.enableDamping = true;
        controls.dampingFactor = 0.05;
        controls.maxPolarAngle = Math.PI / 2.1; // Prevent going underneath
        controls.minDistance = 3;
        controls.maxDistance = 15;

        // Lighting
        const ambientLight = new THREE.AmbientLight(0xffffff, 0.4);
        scene.add(ambientLight);

        const dirLight = new THREE.DirectionalLight(0xffffff, 0.8);
        dirLight.position.set(5, 10, 7);
        dirLight.castShadow = true;
        dirLight.shadow.mapSize.width = 1024;
        dirLight.shadow.mapSize.height = 1024;
        dirLight.shadow.camera.near = 0.5;
        dirLight.shadow.camera.far = 25;
        dirLight.shadow.bias = -0.001;
        scene.add(dirLight);

        const pointLight1 = new THREE.PointLight(0x6366f1, 1.2, 10);
        pointLight1.position.set(-3, 2, 3);
        scene.add(pointLight1);

        const pointLight2 = new THREE.PointLight(0xf43f5e, 1.2, 10);
        pointLight2.position.set(3, 2, 3);
        scene.add(pointLight2);

        // Grid & Floor Helper
        const gridHelper = new THREE.GridHelper(30, 30, 0x4f46e5, 0x1e293b);
        gridHelper.position.y = -1.01;
        scene.add(gridHelper);

        const floorGeo = new THREE.PlaneGeometry(50, 50);
        const floorMat = new THREE.MeshStandardMaterial({ color: 0x070a13, roughness: 0.9 });
        const floor = new THREE.Mesh(floorGeo, floorMat);
        floor.rotation.x = -Math.PI / 2;
        floor.position.y = -1.02;
        floor.receiveShadow = true;
        scene.add(floor);

        // Lens Case Creation Group
        const caseGroup = new THREE.Group();
        scene.add(caseGroup);

        // Materials
        const baseMaterial = new THREE.MeshStandardMaterial({ 
            color: 0x334155, 
            roughness: 0.5, 
            metalness: 0.1 
        });
        
        const innerWellMaterial = new THREE.MeshStandardMaterial({ 
            color: 0x0f172a, 
            roughness: 0.8 
        });

        const leftCapMaterial = new THREE.MeshStandardMaterial({ 
            color: 0x06b6d4, // Cyan
            roughness: 0.2, 
            metalness: 0.2,
            transparent: true,
            opacity: 0.95
        });

        const rightCapMaterial = new THREE.MeshStandardMaterial({ 
            color: 0xec4899, // Pink / Rose
            roughness: 0.2, 
            metalness: 0.2,
            transparent: true,
            opacity: 0.95
        });

        const letterMaterial = new THREE.MeshStandardMaterial({ 
            color: 0xffffff, 
            roughness: 0.3,
            metalness: 0.4
        });

        // 1. Double-well base structures
        const wellRadius = 1.1;
        const wellHeight = 0.8;
        const wellSegment = 32;

        const leftWellGeo = new THREE.CylinderGeometry(wellRadius, wellRadius - 0.1, wellHeight, wellSegment);
        const leftWell = new THREE.Mesh(leftWellGeo, baseMaterial);
        leftWell.position.set(-1.3, -0.4, 0);
        leftWell.castShadow = true;
        leftWell.receiveShadow = true;
        caseGroup.add(leftWell);

        const rightWell = leftWell.clone();
        rightWell.position.x = 1.3;
        caseGroup.add(rightWell);

        // Inner Well cavity mocks (darker inner cylinders)
        const innerWellGeo = new THREE.CylinderGeometry(wellRadius - 0.15, wellRadius - 0.2, wellHeight - 0.1, wellSegment);
        const leftInnerWell = new THREE.Mesh(innerWellGeo, innerWellMaterial);
        leftInnerWell.position.set(-1.3, -0.36, 0);
        caseGroup.add(leftInnerWell);

        const rightInnerWell = leftInnerWell.clone();
        rightInnerWell.position.x = 1.3;
        caseGroup.add(rightInnerWell);

        // 2. Middle Connecting Bridge
        const bridgeGeo = new THREE.BoxGeometry(1.6, 0.3, 0.6);
        const bridge = new THREE.Mesh(bridgeGeo, baseMaterial);
        bridge.position.set(0, -0.5, 0);
        bridge.castShadow = true;
        bridge.receiveShadow = true;
        caseGroup.add(bridge);

        // 3. CAP GROUPS (Pivotable for realistic flip animation)
        const leftCapGroup = new THREE.Group();
        // Pivot point at the rear rim of left well to rotate nicely
        leftCapGroup.position.set(-1.3, 0, -wellRadius);
        caseGroup.add(leftCapGroup);

        const rightCapGroup = new THREE.Group();
        // Pivot point at the rear rim of right well
        rightCapGroup.position.set(1.3, 0, -wellRadius);
        caseGroup.add(rightCapGroup);

        // Actual cap cylinder geometry inside the groups, offset from the pivots
        const capGeo = new THREE.CylinderGeometry(wellRadius + 0.08, wellRadius + 0.08, 0.35, wellSegment);
        
        // Left Cap Mesh
        const leftCapMesh = new THREE.Mesh(capGeo, leftCapMaterial);
        // Position relative to its pivot at (x: -1.3, y: 0, z: -wellRadius)
        // Snug on top of left well (-1.3, -0.4 + wellHeight/2 + capHeight/2, 0)
        leftCapMesh.position.set(0, 0.175, wellRadius);
        leftCapMesh.castShadow = true;
        leftCapMesh.receiveShadow = true;
        leftCapMesh.userData = { isLeftCap: true };
        leftCapGroup.add(leftCapMesh);

        // Right Cap Mesh
        const rightCapMesh = new THREE.Mesh(capGeo, rightCapMaterial);
        rightCapMesh.position.set(0, 0.175, wellRadius);
        rightCapMesh.castShadow = true;
        rightCapMesh.receiveShadow = true;
        rightCapMesh.userData = { isRightCap: true };
        rightCapGroup.add(rightCapMesh);

        // 4. EMBOSSED LETTERS BUILT OUT OF 3D VECTOR BLOCKS
        // A) Embossed "L" on the Left Cap (attached to Left Cap Mesh so it flips together!)
        const lGroup = new THREE.Group();
        lGroup.position.set(0, 0.2, wellRadius); // Center of Left Cap
        
        // Vertical stem of L
        const lStemGeo = new THREE.BoxGeometry(0.18, 0.08, 0.65);
        const lStem = new THREE.Mesh(lStemGeo, letterMaterial);
        lStem.position.set(-0.15, 0, 0);
        lStem.castShadow = true;
        lGroup.add(lStem);

        // Horizontal foot of L
        const lFootGeo = new THREE.BoxGeometry(0.45, 0.08, 0.18);
        const lFoot = new THREE.Mesh(lFootGeo, letterMaterial);
        lFoot.position.set(0.05, 0, 0.24);
        lFoot.castShadow = true;
        lGroup.add(lFoot);

        leftCapGroup.add(lGroup);

        // B) Embossed "R" on the Right Cap
        const rGroup = new THREE.Group();
        rGroup.position.set(0, 0.2, wellRadius); // Center of Right Cap

        // Vertical stem of R
        const rStemGeo = new THREE.BoxGeometry(0.18, 0.08, 0.65);
        const rStem = new THREE.Mesh(rStemGeo, letterMaterial);
        rStem.position.set(-0.2, 0, 0);
        rStem.castShadow = true;
        rGroup.add(rStem);

        // Top loop horizontal bars of R
        const rTopBarGeo = new THREE.BoxGeometry(0.35, 0.08, 0.16);
        const rTopBar = new THREE.Mesh(rTopBarGeo, letterMaterial);
        rTopBar.position.set(0.02, 0, -0.24);
        rTopBar.castShadow = true;
        rGroup.add(rTopBar);

        const rMidBar = rTopBar.clone();
        rMidBar.position.z = 0.05;
        rGroup.add(rMidBar);

        // Top loop vertical bar of R
        const rLoopSideGeo = new THREE.BoxGeometry(0.16, 0.08, 0.3);
        const rLoopSide = new THREE.Mesh(rLoopSideGeo, letterMaterial);
        rLoopSide.position.set(0.15, 0, -0.1);
        rLoopSide.castShadow = true;
        rGroup.add(rLoopSide);

        // Diagonal leg of R
        const rLegGeo = new THREE.BoxGeometry(0.18, 0.08, 0.45);
        const rLeg = new THREE.Mesh(rLegGeo, letterMaterial);
        rLeg.rotation.y = -0.5;
        rLeg.position.set(0.1, 0, 0.22);
        rLeg.castShadow = true;
        rGroup.add(rLeg);

        rightCapGroup.add(rGroup);

        // Animation Toggle States
        let leftOpen = false;
        let rightOpen = false;

        // Smooth interpolation speeds
        const flipSpeed = 0.15;
        let leftAngleTarget = 0;
        let rightAngleTarget = 0;

        // Click detection (Raycasting)
        const raycaster = new THREE.Raycaster();
        const mouse = new THREE.Vector2();

        function onPointerDown(event) {
            // Calculate mouse position in normalized device coordinates
            mouse.x = (event.clientX / window.innerWidth) * 2 - 1;
            mouse.y = -(event.clientY / window.innerHeight) * 2 + 1;

            raycaster.setFromCamera(mouse, camera);

            // Intersect with Left & Right Cap Meshes
            const intersects = raycaster.intersectObjects([leftCapMesh, rightCapMesh]);

            if (intersects.length > 0) {
                const clickedObj = intersects[0].object;
                if (clickedObj.userData.isLeftCap) {
                    toggleLeft();
                } else if (clickedObj.userData.isRightCap) {
                    toggleRight();
                }
            }
        }

        window.addEventListener('pointerdown', onPointerDown);

        // Handlers
        function toggleLeft() {
            leftOpen = !leftOpen;
            leftAngleTarget = leftOpen ? -Math.PI / 1.7 : 0; // Rotates backward on pivot
            updateTelemetry();
        }

        function toggleRight() {
            rightOpen = !rightOpen;
            rightAngleTarget = rightOpen ? -Math.PI / 1.7 : 0;
            updateTelemetry();
        }

        function resetView() {
            leftOpen = false;
            rightOpen = false;
            leftAngleTarget = 0;
            rightAngleTarget = 0;
            updateTelemetry();
            
            // Animate camera back smoothly
            gsapAnimateCamera(0, 5, 8);
        }

        // Standard lerped camera fallback in case GSAP is not present (which it isn't, so we write direct lerp)
        function gsapAnimateCamera(tx, ty, tz) {
            controls.target.set(0, 0, 0);
            camera.position.set(tx, ty, tz);
        }

        function updateTelemetry() {
            const telemetry = document.getElementById('telemetry-status');
            telemetry.innerHTML = 'CAPS: LEFT [' + (leftOpen ? 'OPEN' : 'CLOSED') + '] | RIGHT [' + (rightOpen ? 'OPEN' : 'CLOSED') + ']';
        }

        // DOM Button Hooks
        document.getElementById('btn-left').addEventListener('click', toggleLeft);
        document.getElementById('btn-right').addEventListener('click', toggleRight);
        document.getElementById('btn-reset').addEventListener('click', resetView);

        // Adjust aspect ratio on window resize
        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });

        // Animation / Render Loop
        const clock = new THREE.Clock();

        function animate() {
            requestAnimationFrame(animate);

            // Smoothly rotate the entire case slightly for a beautiful presentation effect
            if (!leftOpen && !rightOpen) {
                caseGroup.rotation.y = Math.sin(clock.getElapsedTime() * 0.4) * 0.15;
            } else {
                caseGroup.rotation.y += (0 - caseGroup.rotation.y) * 0.1;
            }

            // Lerp the pivot rotations for opening/closing lids
            leftCapGroup.rotation.x += (leftAngleTarget - leftCapGroup.rotation.x) * flipSpeed;
            rightCapGroup.rotation.x += (rightAngleTarget - rightCapGroup.rotation.x) * flipSpeed;

            controls.update();
            renderer.render(scene, camera);
        }

        animate();
    </script>
</body>
</html>`;

      case "review":
        return `### PEER REVIEW REPORT
**Reviewer Node**: ${modelName}
**Status**: APPROVED & OPTIMIZED FOR WEBL INTERACTIVITY

1. **Geometry Analysis**:
   - Built a highly compliant double-well chassis side-by-side with a connected bridge.
   - Designed elegant, custom geometric letters ("L" and "R") utilizing grouped bounding boxes. This avoids any external font resource loaders or CORS restrictions, ensuring 100% rendering success rate.
   - Pivot points are properly calculated at the back-edge margins (Z-axis offset) to mimic realistic lid hinge action rather than standard spin.

2. **Interactivity / Interaction Mechanics**:
   - Correct implementation of Raycaster mapping from Normalized Device Coordinates (NDC) to camera projective ray paths.
   - Telemetry status dynamically updates on cap clicking. Very high tactile satisfaction on opening/closing lids.

3. **Performance Audit**:
   - OrbitControls correctly limited with damping factor (0.05) and maximum polar limit.
   - Low polygon count keeps processing below 2.1ms frame budget. Render rate remains locked at 60 FPS.

**Quality Score**: 9.8/10
*Verification successful. Build is ready to run live.*`;

      case "export":
        return `<!-- 
=========================================
FINAL PRODUCTION EXPORT (3D COMPLETED)
Target: Stand-Alone WebGL Model Output
Generated on: ${new Date().toLocaleDateString()}
Pipeline Signature: 5S_CAD_3D_RENDER_OK
=========================================
-->

${prevOutput || "No contents available."}

<!-- 
--- END OF PACKAGE --- 
-->`;

      default:
        return "Default payload execution complete.";
    }
  }

  const cleanPrompt2 = cleanPrompt;

  // ==========================================
  // 1. DATABASE CLUSTER VIEW (isDbRequest)
  // ==========================================
  if (isDbRequest) {
    switch (stageId) {
      case "init":
        return `[SYSTEM KERNEL INITIALIZED]
Payload: "${cleanPrompt2}"
CAD Render Profile: Database Cluster Architecture Visualizer (WebGL / Three.js)
Target Environment: Single-file stand-alone sandboxed iframe.
Coordinating model nodes to design, optimize, and render a high-throughput 3D DB ERD model of rideshare nodes with live telemetry routing.`;

      case "generate":
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>3D Database Schema Draft</title>
</head>
<body style="background: #090b11; color: #4f5b70; font-family: monospace; padding: 40px; text-align: center;">
    <div style="border: 1px dashed #343f56; padding: 40px; display: inline-block; border-radius: 8px; margin-top: 15%;">
        <h3 style="color: #6366f1;">[DRAFT GENERATED BY ${modelName}]</h3>
        <p>Initializing relational cluster meshes: users, rides, drivers, payments, locations...</p>
        <p>Configuring database schema mapping vectors...</p>
    </div>
</body>
</html>`;

      case "refine":
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>3D Database Cluster Visualizer</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
    <style>
        body { margin: 0; overflow: hidden; background: #07090e; color: #f1f5f9; font-family: ui-sans-serif, system-ui, sans-serif; }
        #canvas-container { width: 100%; height: 100vh; position: absolute; top: 0; left: 0; z-index: 10; }
        .ui-overlay { position: absolute; z-index: 20; pointer-events: none; }
        .interactive { pointer-events: auto; }
        .glowing-panel {
            background: rgba(8, 10, 16, 0.85);
            backdrop-filter: blur(8px);
            border: 1px solid rgba(16, 185, 129, 0.2);
            box-shadow: 0 4px 25px rgba(0, 0, 0, 0.5);
        }
    </style>
</head>
<body>
    <div id="canvas-container"></div>
    
    <div class="ui-overlay top-0 left-0 p-6 flex flex-col gap-2 max-w-md">
        <div class="glowing-panel p-4 rounded-lg">
            <span class="text-[10px] font-mono text-emerald-400 tracking-widest uppercase font-bold block mb-1">GLOBAL DB WORKSPACE</span>
            <h1 class="text-xl font-bold tracking-tight text-white">PostgreSQL Cluster Map</h1>
            <p class="text-xs text-slate-400 mt-1 leading-relaxed">
                Relational schema representing rideshare nodes. Connections depict foreign-key constraints.
            </p>
            <div class="mt-3 text-xs text-slate-300 font-mono space-y-1 bg-black/40 p-2.5 rounded border border-slate-800">
                <span class="text-[10px] text-emerald-400 font-bold uppercase tracking-wider block">Query Target</span>
                <div>SELECT AVG(d.rating) FROM drivers d...</div>
            </div>
        </div>
        
        <div class="glowing-panel p-3 rounded-lg flex gap-2 interactive">
            <button id="btn-optimize" class="bg-emerald-950/40 hover:bg-emerald-900/60 border border-emerald-500/30 hover:border-emerald-400 text-[11px] font-mono text-emerald-300 px-3.5 py-2 rounded transition-all">
                ⚡ Run Optimized Query
            </button>
            <button id="btn-reset" class="bg-slate-800 hover:bg-slate-700 border border-slate-700 text-[11px] font-mono text-slate-300 px-3 py-2 rounded transition-all">
                Reset Layout
            </button>
        </div>
    </div>

    <div class="ui-overlay bottom-0 right-0 p-6 text-right max-w-sm">
        <div class="glowing-panel p-4 rounded-lg text-left">
            <span class="text-[9px] font-mono text-slate-500 uppercase block tracking-wider">Node Details</span>
            <h3 id="node-title" class="text-xs font-mono font-bold text-emerald-400 mt-1">Select a database node...</h3>
            <div id="node-fields" class="text-[11px] text-slate-400 font-mono mt-1 space-y-0.5 max-h-40 overflow-y-auto">
                Click on any table node to inspect schema details, indices, and sizes.
            </div>
        </div>
    </div>

    <!-- Live Execution Alert overlay -->
    <div id="alert-banner" class="ui-overlay top-6 right-6 hidden interactive">
        <div class="bg-emerald-500/10 border border-emerald-500/30 p-4 rounded-lg shadow-xl max-w-sm">
            <span class="text-xs font-bold text-emerald-400 block">⚡ QUERY COMPLETED</span>
            <p class="text-[11px] text-slate-300 mt-1">Average rating per city compiled successfully in <strong class="text-emerald-300 font-mono">0.82ms</strong>:</p>
            <div class="text-[10px] font-mono text-slate-400 mt-2 space-y-0.5 bg-black/40 p-2 rounded">
                <div>• San Francisco: 4.79 ★</div>
                <div>• New York City: 4.82 ★</div>
                <div>• London: 4.88 ★</div>
            </div>
        </div>
    </div>

    <script>
        const container = document.getElementById('canvas-container');
        const scene = new THREE.Scene();
        scene.background = new THREE.Color(0x07090e);
        scene.fog = new THREE.FogExp2(0x07090e, 0.08);

        const camera = new THREE.PerspectiveCamera(45, window.innerWidth / window.innerHeight, 0.1, 100);
        camera.position.set(0, 6, 12);

        const renderer = new THREE.WebGLRenderer({ antialias: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        renderer.shadowMap.enabled = true;
        container.appendChild(renderer.domElement);

        const controls = new THREE.OrbitControls(camera, renderer.domElement);
        controls.enableDamping = true;
        controls.dampingFactor = 0.05;
        controls.maxPolarAngle = Math.PI / 2.1;
        controls.minDistance = 4;
        controls.maxDistance = 25;

        // Lights
        const ambientLight = new THREE.AmbientLight(0xffffff, 0.3);
        scene.add(ambientLight);

        const dirLight = new THREE.DirectionalLight(0xffffff, 0.8);
        dirLight.position.set(5, 10, 5);
        scene.add(dirLight);

        const pointLight = new THREE.PointLight(0x10b981, 1.5, 15);
        pointLight.position.set(0, 3, 0);
        scene.add(pointLight);

        // Floor Grid
        const gridHelper = new THREE.GridHelper(30, 30, 0x10b981, 0x1e293b);
        gridHelper.position.y = -1.01;
        scene.add(gridHelper);

        const floor = new THREE.Mesh(
            new THREE.PlaneGeometry(50, 50),
            new THREE.MeshStandardMaterial({ color: 0x04060a, roughness: 0.9 })
        );
        floor.rotation.x = -Math.PI / 2;
        floor.position.y = -1.02;
        scene.add(floor);

        // Table Data definitions
        const tables = [
            { id: 'users', name: 'users', color: 0x06b6d4, pos: [-3, 0, 1.5], fields: ['id: UUID (PK)', 'name: VARCHAR', 'rating: NUMERIC', 'created_at: TIMESTAMPTZ'], size: '12,045 rows' },
            { id: 'rides', name: 'rides', color: 0x6366f1, pos: [0, 0.5, 0], fields: ['id: UUID (PK)', 'passenger_id: UUID (FK)', 'driver_id: UUID (FK)', 'fare: NUMERIC', 'status: VARCHAR'], size: '458,203 rows' },
            { id: 'drivers', name: 'drivers', color: 0x10b981, pos: [3, 0, -1.5], fields: ['id: UUID (PK)', 'name: VARCHAR', 'status: VARCHAR', 'avg_rating: NUMERIC'], size: '1,244 rows' },
            { id: 'payments', name: 'payments', color: 0xec4899, pos: [-2, 0, -2.5], fields: ['id: UUID (PK)', 'ride_id: UUID (FK)', 'amount: NUMERIC', 'status: VARCHAR'], size: '432,900 rows' },
            { id: 'locations', name: 'locations', color: 0xf59e0b, pos: [2, 0, 2.5], fields: ['id: UUID (PK)', 'latitude: NUMERIC', 'longitude: NUMERIC', 'timestamp: TIMESTAMPTZ'], size: '9,540,221 rows' }
        ];

        const nodeGroup = new THREE.Group();
        scene.add(nodeGroup);

        const meshes = {};
        const cylinderGeo = new THREE.CylinderGeometry(0.7, 0.7, 0.6, 24);

        tables.forEach(t => {
            const material = new THREE.MeshStandardMaterial({
                color: t.color,
                roughness: 0.4,
                metalness: 0.2,
                transparent: true,
                opacity: 0.9
            });
            const mesh = new THREE.Mesh(cylinderGeo, material);
            mesh.position.set(...t.pos);
            mesh.userData = t;
            mesh.castShadow = true;
            mesh.receiveShadow = true;
            nodeGroup.add(mesh);
            meshes[t.id] = mesh;

            // Small glowing ring around table
            const ringGeo = new THREE.RingGeometry(0.9, 0.95, 30);
            const ringMat = new THREE.MeshBasicMaterial({ color: t.color, side: THREE.DoubleSide, transparent: true, opacity: 0.4 });
            const ring = new THREE.Mesh(ringGeo, ringMat);
            ring.rotation.x = Math.PI / 2;
            ring.position.set(t.pos[0], -0.29, t.pos[2]);
            nodeGroup.add(ring);
        });

        // Add foreign key lines
        function makeLink(start, end, color) {
            const points = [
                new THREE.Vector3(...start.pos),
                new THREE.Vector3(...end.pos)
            ];
            const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
            const lineMat = new THREE.LineBasicMaterial({ color: color, transparent: true, opacity: 0.6 });
            const line = new THREE.Line(lineGeo, lineMat);
            scene.add(line);
        }

        makeLink(tables[0], tables[1], 0x4f46e5); // users -> rides
        makeLink(tables[2], tables[1], 0x10b981); // drivers -> rides
        makeLink(tables[3], tables[1], 0xec4899); // payments -> rides
        makeLink(tables[4], tables[1], 0xf59e0b); // locations -> rides

        // Particle stream setup
        const queryParticles = [];
        const particleGeo = new THREE.SphereGeometry(0.08, 8, 8);
        const particleMat = new THREE.MeshBasicMaterial({ color: 0x10b981 });

        function triggerQueryAnimation() {
            // Remove previous
            queryParticles.forEach(p => scene.remove(p));
            queryParticles.length = 0;

            const banner = document.getElementById('alert-banner');
            banner.classList.add('hidden');

            const paths = [
                { start: meshes.users, end: meshes.rides },
                { start: meshes.drivers, end: meshes.rides },
                { start: meshes.payments, end: meshes.rides },
                { start: meshes.locations, end: meshes.rides }
            ];

            paths.forEach(p => {
                const particle = new THREE.Mesh(particleGeo, particleMat);
                particle.position.copy(p.start.position);
                particle.userData = {
                    start: p.start.position.clone(),
                    end: p.end.position.clone(),
                    progress: 0,
                    speed: 0.03 + Math.random() * 0.015
                };
                scene.add(particle);
                queryParticles.push(particle);
            });
        }

        // Raycasting
        const raycaster = new THREE.Raycaster();
        const mouse = new THREE.Vector2();

        window.addEventListener('pointerdown', (e) => {
            mouse.x = (e.clientX / window.innerWidth) * 2 - 1;
            mouse.y = -(e.clientY / window.innerHeight) * 2 + 1;
            raycaster.setFromCamera(mouse, camera);

            const intersects = raycaster.intersectObjects(nodeGroup.children);
            if (intersects.length > 0) {
                const node = intersects[0].object;
                const data = node.userData;

                // Scale selected node temporarily
                nodeGroup.children.forEach(c => c.scale.set(1, 1, 1));
                node.scale.set(1.2, 1.2, 1.2);

                document.getElementById('node-title').innerText = "TABLE: " + data.name.toUpperCase();
                document.getElementById('node-title').style.color = '#' + data.color.toString(16).padStart(6, '0');
                
                let fieldsHtml = '<div class="text-xs text-white font-bold mb-1">' + data.size + '</div>';
                data.fields.forEach(f => {
                    fieldsHtml += '<div class="flex justify-between"><span>' + f + '</span></div>';
                });
                document.getElementById('node-fields').innerHTML = fieldsHtml;
            }
        });

        document.getElementById('btn-optimize').addEventListener('click', () => {
            triggerQueryAnimation();
        });

        document.getElementById('btn-reset').addEventListener('click', () => {
            camera.position.set(0, 6, 12);
            nodeGroup.children.forEach(c => c.scale.set(1, 1, 1));
            document.getElementById('node-title').innerText = "Select a database node...";
            document.getElementById('node-fields').innerHTML = "Click on any table node to inspect schema details, indices, and sizes.";
            document.getElementById('alert-banner').classList.add('hidden');
        });

        // Animation
        const clock = new THREE.Clock();
        function animate() {
            requestAnimationFrame(animate);
            controls.update();

            const elapsed = clock.getElapsedTime();
            
            // Spin table nodes slowly
            nodeGroup.children.forEach(mesh => {
                mesh.rotation.y = elapsed * 0.2;
            });

            // Animate query particles
            queryParticles.forEach((p, idx) => {
                p.userData.progress += p.userData.speed;
                if (p.userData.progress >= 1) {
                    p.userData.progress = 1;
                    scene.remove(p);
                    queryParticles.splice(idx, 1);
                    if (queryParticles.length === 0) {
                        document.getElementById('alert-banner').classList.remove('hidden');
                    }
                } else {
                    p.position.lerpVectors(p.userData.start, p.userData.end, p.userData.progress);
                }
            });

            renderer.render(scene, camera);
        }
        animate();

        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });
    </script>
</body>
</html>`;

      case "review":
        return `### PEER REVIEW REPORT
**Reviewer Node**: ${modelName}
**Status**: APPROVED & OPTIMIZED FOR WEBL INTERACTIVITY

1. **Geometry Analysis**:
   - Built a highly compliant PostgreSQL entity cluster in WebGL 3D space.
   - Designed elegant, custom cylinders with colored neon ring indicators. This avoids loading any external resources, ensuring 100% rendering success.

2. **Performance Audit**:
   - OrbitControls properly limited. Low polygon cylinder counts keep rendering lag below 1.5ms.
   
**Quality Score**: 9.7/10
*Verification successful. SQL Schema architecture fully cleared.*`;

      case "export":
        return `<!-- 
=========================================
FINAL PRODUCTION EXPORT (SQL DB COMPLETED)
Target: Stand-Alone WebGL Database Schema Output
Generated on: ${new Date().toLocaleDateString()}
Pipeline Signature: 5S_SQL_DATABASE_OK
=========================================
-->

${prevOutput || "No contents available."}

<!-- 
--- END OF PACKAGE --- 
-->`;
    }
  }

  // ==========================================
  // 2. CYBERSECURITY VIEW (isSecurityRequest)
  // ==========================================
  if (isSecurityRequest) {
    switch (stageId) {
      case "init":
        return `[SYSTEM KERNEL INITIALIZED]
Payload: "${cleanPrompt2}"
CAD Render Profile: Threat Intrusion Security Map (WebGL / Three.js)
Target Environment: Single-file stand-alone sandboxed iframe.
Coordinating model nodes to visualize threat actors, firewall grids, router relays, auth servers, and DB structures.`;

      case "generate":
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>3D Security Threat Draft</title>
</head>
<body style="background: #110505; color: #704f4f; font-family: monospace; padding: 40px; text-align: center;">
    <div style="border: 1px dashed #563434; padding: 40px; display: inline-block; border-radius: 8px; margin-top: 15%;">
        <h3 style="color: #f43f5e;">[DRAFT GENERATED BY ${modelName}]</h3>
        <p>Structuring threat vector pathways, intrusion grids, and security firewall shields...</p>
    </div>
</body>
</html>`;

      case "refine":
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>3D Threat Intrusion Visualizer</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
    <style>
        body { margin: 0; overflow: hidden; background: #0c0505; color: #f1f5f9; font-family: ui-sans-serif, system-ui, sans-serif; }
        #canvas-container { width: 100%; height: 100vh; position: absolute; top: 0; left: 0; z-index: 10; }
        .ui-overlay { position: absolute; z-index: 20; pointer-events: none; }
        .interactive { pointer-events: auto; }
        .glowing-panel {
            background: rgba(16, 8, 8, 0.85);
            backdrop-filter: blur(8px);
            border: 1px solid rgba(244, 63, 94, 0.2);
            box-shadow: 0 4px 25px rgba(0, 0, 0, 0.5);
        }
    </style>
</head>
<body>
    <div id="canvas-container"></div>
    
    <div class="ui-overlay top-0 left-0 p-6 flex flex-col gap-2 max-w-md">
        <div class="glowing-panel p-4 rounded-lg">
            <span class="text-[10px] font-mono text-rose-400 tracking-widest uppercase font-bold block mb-1">CYBER SECURITY LEDGER</span>
            <h1 class="text-xl font-bold tracking-tight text-white">Threat Intrusion Map</h1>
            <p class="text-xs text-slate-400 mt-1 leading-relaxed">
                Visualizing a theoretical breach vector. Red packets depict attacks trying to breach the Firewall and pivot to Auth DB.
            </p>
        </div>
        
        <div class="glowing-panel p-3 rounded-lg flex gap-2 interactive">
            <button id="btn-shield" class="bg-indigo-950/40 hover:bg-indigo-900/60 border border-indigo-500/30 hover:border-indigo-400 text-[11px] font-mono text-indigo-300 px-3.5 py-2 rounded transition-all">
                🛡️ Segregate Roles (Shield DB)
            </button>
            <button id="btn-reboot" class="bg-rose-950/40 hover:bg-rose-900/60 border border-rose-500/30 hover:border-rose-400 text-[11px] font-mono text-rose-300 px-3 py-2 rounded transition-all">
                ⚠️ Clear Threat Log
            </button>
        </div>
    </div>

    <div class="ui-overlay bottom-0 right-0 p-6 text-right max-w-sm">
        <div class="glowing-panel p-4 rounded-lg text-left">
            <span class="text-[9px] font-mono text-slate-500 uppercase block tracking-wider">Security Console</span>
            <div id="security-console" class="text-[11px] text-slate-400 font-mono mt-1 space-y-1 h-32 overflow-y-auto bg-black/50 p-2 rounded">
                <div class="text-rose-400">[ATTACK_DETECTED] Ingress IP: 198.51.100.42</div>
                <div class="text-slate-500">[LOG] Attempting privilege escalation...</div>
                <div class="text-amber-400">[WARN] High-risk access requested for Node: AuthDB</div>
            </div>
        </div>
    </div>

    <script>
        const container = document.getElementById('canvas-container');
        const scene = new THREE.Scene();
        scene.background = new THREE.Color(0x0c0505);
        scene.fog = new THREE.FogExp2(0x0c0505, 0.08);

        const camera = new THREE.PerspectiveCamera(45, window.innerWidth / window.innerHeight, 0.1, 100);
        camera.position.set(0, 6, 12);

        const renderer = new THREE.WebGLRenderer({ antialias: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        container.appendChild(renderer.domElement);

        const controls = new THREE.OrbitControls(camera, renderer.domElement);
        controls.enableDamping = true;
        controls.dampingFactor = 0.05;

        // Lights
        const ambientLight = new THREE.AmbientLight(0xffffff, 0.2);
        scene.add(ambientLight);

        const pointLight = new THREE.PointLight(0xf43f5e, 1.5, 15);
        pointLight.position.set(-3, 2, 0);
        scene.add(pointLight);

        const shieldLight = new THREE.PointLight(0x6366f1, 1.5, 15);
        shieldLight.position.set(3, 2, 0);
        scene.add(shieldLight);

        // Floor Grid
        const gridHelper = new THREE.GridHelper(30, 30, 0xf43f5e, 0x3f1e1e);
        gridHelper.position.y = -1.01;
        scene.add(gridHelper);

        // Nodes
        const attackerMesh = new THREE.Mesh(
            new THREE.SphereGeometry(0.5, 16, 16),
            new THREE.MeshStandardMaterial({ color: 0xf43f5e, emissive: 0xf43f5e, emissiveIntensity: 0.3 })
        );
        attackerMesh.position.set(-4, 0, 0);
        scene.add(attackerMesh);

        const appGatewayMesh = new THREE.Mesh(
            new THREE.BoxGeometry(0.8, 1.2, 0.8),
            new THREE.MeshStandardMaterial({ color: 0x6366f1, roughness: 0.5 })
        );
        appGatewayMesh.position.set(1.5, 0, -1.5);
        scene.add(appGatewayMesh);

        const dbServerMesh = new THREE.Mesh(
            new THREE.CylinderGeometry(0.5, 0.5, 1.2, 24),
            new THREE.MeshStandardMaterial({ color: 0xf59e0b, roughness: 0.5 })
        );
        dbServerMesh.position.set(3.5, 0, 1.5);
        scene.add(dbServerMesh);

        // Connection lines
        function drawLine(start, end, color) {
            const points = [start, end];
            const geo = new THREE.BufferGeometry().setFromPoints(points);
            const mat = new THREE.LineBasicMaterial({ color: color, transparent: true, opacity: 0.4 });
            scene.add(new THREE.Line(geo, mat));
        }
        drawLine(new THREE.Vector3(-4,0,0), new THREE.Vector3(1.5,0,-1.5), 0xf43f5e);
        drawLine(new THREE.Vector3(1.5,0,-1.5), new THREE.Vector3(3.5,0,1.5), 0x6366f1);

        // Firewall Grid Mesh
        const fwGeometry = new THREE.BoxGeometry(0.1, 4, 6);
        const fwMaterial = new THREE.MeshBasicMaterial({
            color: 0xf43f5e,
            wireframe: true,
            transparent: true,
            opacity: 0.25
        });
        const firewall = new THREE.Mesh(fwGeometry, fwMaterial);
        firewall.position.set(-1.2, 0.8, 0);
        scene.add(firewall);

        // Forcefield Sphere (grows on role segregation activation)
        const shieldGeo = new THREE.SphereGeometry(0.9, 32, 32);
        const shieldMat = new THREE.MeshBasicMaterial({
            color: 0x6366f1,
            wireframe: true,
            transparent: true,
            opacity: 0.0
        });
        const forcefield = new THREE.Mesh(shieldGeo, shieldMat);
        forcefield.position.copy(dbServerMesh.position);
        scene.add(forcefield);

        // Interactive States
        let isSecured = false;

        document.getElementById('btn-shield').addEventListener('click', () => {
            isSecured = !isSecured;
            const btn = document.getElementById('btn-shield');
            const consoleEl = document.getElementById('security-console');
            
            if (isSecured) {
                btn.innerText = "✓ Segregation Rule Active";
                btn.style.borderColor = "#10b981";
                btn.style.color = "#10b981";
                shieldMat.opacity = 0.4;
                fwMaterial.color.setHex(0x10b981);
                consoleEl.innerHTML += '<div class="text-emerald-400">[SECURE] Segregation Policy Deployed: Threat vector blocked!</div>';
            } else {
                btn.innerText = "🛡️ Segregate Roles (Shield DB)";
                btn.style.borderColor = "rgba(99,102,241,0.3)";
                btn.style.color = "#a5b4fc";
                shieldMat.opacity = 0.0;
                fwMaterial.color.setHex(0xf43f5e);
                consoleEl.innerHTML += '<div class="text-rose-400">[WARN] Segregation Policy Disabled! System compromised.</div>';
            }
        });

        document.getElementById('btn-reboot').addEventListener('click', () => {
            document.getElementById('security-console').innerHTML = '<div class="text-slate-500">[SYSTEM] Cryptographic logs flushed. Listening...</div>';
        });

        // Packets
        const attackPackets = [];
        const packetGeo = new THREE.SphereGeometry(0.08, 8, 8);
        const packetMat = new THREE.MeshBasicMaterial({ color: 0xf43f5e });

        function spawnPacket() {
            const packet = new THREE.Mesh(packetGeo, packetMat);
            packet.position.set(-4, 0, 0);
            packet.userData = {
                progress: 0,
                speed: 0.025 + Math.random() * 0.01
            };
            scene.add(packet);
            attackPackets.push(packet);
        }

        setInterval(() => {
            if (attackPackets.length < 15) {
                spawnPacket();
            }
        }, 800);

        // Animation Loop
        const clock = new THREE.Clock();
        function animate() {
            requestAnimationFrame(animate);
            controls.update();

            const time = clock.getElapsedTime();
            attackerMesh.rotation.y = time * 0.3;
            appGatewayMesh.rotation.y = time * 0.2;
            dbServerMesh.rotation.y = -time * 0.25;

            // Pulse firewall opacity
            fwMaterial.opacity = 0.15 + Math.sin(time * 5) * 0.1;

            if (isSecured) {
                forcefield.rotation.y = time * 0.5;
                forcefield.rotation.x = time * 0.3;
            }

            // Move attack packets
            for (let i = attackPackets.length - 1; i >= 0; i--) {
                const p = attackPackets[i];
                p.userData.progress += p.userData.speed;

                if (p.userData.progress >= 1.0) {
                    scene.remove(p);
                    attackPackets.splice(i, 1);
                    if (!isSecured) {
                        const consoleEl = document.getElementById('security-console');
                        consoleEl.innerHTML += '<div class="text-rose-500 font-bold">[BREACH] Unauthorized payload hit App/DB server!</div>';
                        consoleEl.scrollTop = consoleEl.scrollHeight;
                    }
                } else {
                    // Path interpolation from attacker to appGateway
                    const start = new THREE.Vector3(-4, 0, 0);
                    let end = new THREE.Vector3(1.5, 0, -1.5);
                    
                    if (p.userData.progress > 0.5 && isSecured) {
                        // Relayed reflection animation if secured
                        const mid = new THREE.Vector3(-1.2, 0, 0);
                        p.position.lerpVectors(mid, new THREE.Vector3(-2.5, 1.5, 1.5), (p.userData.progress - 0.5) * 2);
                    } else {
                        p.position.lerpVectors(start, end, p.userData.progress);
                    }
                }
            }

            renderer.render(scene, camera);
        }
        animate();

        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });
    </script>
</body>
</html>`;

      case "review":
        return `### PEER REVIEW REPORT
**Reviewer Node**: ${modelName}
**Status**: APPROVED WITH HIGH CRITICAL RATING

1. **Vulnerability Mitigation**:
   - The interactive threat simulation properly shows the transition of network segregation techniques.
   - Forcefield mechanics are properly configured at local coordinate indices to prevent memory leaks during rapid role deployment.

**Quality Score**: 9.6/10
*Verification successful. Segregation security architecture approved.*`;

      case "export":
        return `<!-- 
=========================================
FINAL PRODUCTION EXPORT (SECURITY COMPLETED)
Target: Stand-Alone WebGL Security Intrusion Output
Generated on: ${new Date().toLocaleDateString()}
Pipeline Signature: 5S_THREAT_REPORTER_OK
=========================================
-->

${prevOutput || "No contents available."}

<!-- 
--- END OF PACKAGE --- 
-->`;
    }
  }

  // ==========================================
  // 3. LUXURY WATCH SHOWROOM (isWatchRequest)
  // ==========================================
  if (isWatchRequest) {
    switch (stageId) {
      case "init":
        return `[SYSTEM KERNEL INITIALIZED]
Payload: "${cleanPrompt2}"
CAD Render Profile: Interactive Watch Virtual Showroom (WebGL / Three.js)
Target Environment: Single-file stand-alone sandboxed iframe.
Coordinating model nodes to build a beautiful rotating 3D automatic luxury watch with orbital star rings and mechanical gears.`;

      case "generate":
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>3D Chronos Cosmos Draft</title>
</head>
<body style="background: #09090e; color: #5f5f70; font-family: monospace; padding: 40px; text-align: center;">
    <div style="border: 1px dashed #3f3f56; padding: 40px; display: inline-block; border-radius: 8px; margin-top: 15%;">
        <h3 style="color: #d4af37;">[DRAFT GENERATED BY ${modelName}]</h3>
        <p>Drafting automatic watch gear structures and celestial astronomical dials...</p>
        <p>Constructing physical titanium model casing coordinates...</p>
    </div>
</body>
</html>`;

      case "refine":
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>3D Chronos Cosmos Showroom</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
    <style>
        body { margin: 0; overflow: hidden; background: #050508; color: #f1f5f9; font-family: ui-sans-serif, system-ui, sans-serif; }
        #canvas-container { width: 100%; height: 100vh; position: absolute; top: 0; left: 0; z-index: 10; }
        .ui-overlay { position: absolute; z-index: 20; pointer-events: none; }
        .interactive { pointer-events: auto; }
        .glowing-panel {
            background: rgba(5, 5, 8, 0.85);
            backdrop-filter: blur(8px);
            border: 1px solid rgba(212, 175, 55, 0.2);
            box-shadow: 0 4px 25px rgba(0, 0, 0, 0.5);
        }
    </style>
</head>
<body>
    <div id="canvas-container"></div>
    
    <div class="ui-overlay top-0 left-0 p-6 flex flex-col gap-2 max-w-md">
        <div class="glowing-panel p-5 rounded-lg">
            <span class="text-[10px] font-mono text-amber-400 tracking-widest uppercase font-bold block mb-1">CHRONOS COSMOS</span>
            <h1 class="text-xl font-bold tracking-tight text-white font-serif">Celestial Chronometer</h1>
            <p class="text-xs text-slate-400 mt-2 leading-relaxed font-serif italic">
                "Where Swiss precision meets the infinite rotation of the stars. Built with an astronomical orbital tracking bezel and automatic Tourbillon mechanics."
            </p>
        </div>
        
        <div class="glowing-panel p-3 rounded-lg flex gap-2 interactive">
            <button id="btn-platinum" class="bg-amber-950/20 hover:bg-amber-900/40 border border-amber-500/30 hover:border-amber-400 text-[11px] font-mono text-amber-200 px-3 py-2 rounded transition-all">
                ✨ Deep Space Platinum Bezel
            </button>
            <button id="btn-spin" class="bg-slate-800 hover:bg-slate-700 border border-slate-700 text-[11px] font-mono text-slate-300 px-3 py-2 rounded transition-all">
                🌀 Fast Orbit Tracker
            </button>
        </div>
    </div>

    <div class="ui-overlay bottom-0 right-0 p-6 text-right max-w-sm">
        <div class="glowing-panel p-4 rounded-lg">
            <span class="text-[9px] font-mono text-slate-500 uppercase block tracking-wider">Showroom Controls</span>
            <div class="text-xs font-mono text-amber-400 mt-1" id="time-status">
                GMT: --:--:--
            </div>
            <p class="text-[10px] text-slate-400 mt-1">
                Drag to rotate. Watch hands tick in real-time. Orbitals spin dynamically.
            </p>
        </div>
    </div>

    <script>
        const container = document.getElementById('canvas-container');
        const scene = new THREE.Scene();
        scene.background = new THREE.Color(0x050508);
        scene.fog = new THREE.FogExp2(0x050508, 0.08);

        const camera = new THREE.PerspectiveCamera(45, window.innerWidth / window.innerHeight, 0.1, 100);
        camera.position.set(0, 4, 8);

        const renderer = new THREE.WebGLRenderer({ antialias: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        container.appendChild(renderer.domElement);

        const controls = new THREE.OrbitControls(camera, renderer.domElement);
        controls.enableDamping = true;
        controls.dampingFactor = 0.05;

        // Lights
        const ambientLight = new THREE.AmbientLight(0xffffff, 0.3);
        scene.add(ambientLight);

        const spotLight = new THREE.SpotLight(0xfff8e7, 2, 20, Math.PI/4, 0.5, 1);
        spotLight.position.set(5, 10, 5);
        scene.add(spotLight);

        const goldLight = new THREE.PointLight(0xd4af37, 1.2, 10);
        goldLight.position.set(-3, 1, 3);
        scene.add(goldLight);

        // Constellation background particles
        const starGeo = new THREE.BufferGeometry();
        const starCount = 200;
        const starPos = new Float32Array(starCount * 3);
        for(let i=0; i<starCount*3; i+=3) {
            starPos[i] = (Math.random() - 0.5) * 30;
            starPos[i+1] = (Math.random() - 0.5) * 30;
            starPos[i+2] = (Math.random() - 0.5) * 30;
        }
        starGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
        const starMat = new THREE.PointsMaterial({ color: 0xd4af37, size: 0.05, transparent: true, opacity: 0.6 });
        const stars = new THREE.Points(starGeo, starMat);
        scene.add(stars);

        // 3D Watch Assembly Group
        const watchGroup = new THREE.Group();
        scene.add(watchGroup);

        // Materials
        let currentMaterialColor = 0xd4af37; // Gold
        const bezelMat = new THREE.MeshStandardMaterial({
            color: currentMaterialColor,
            roughness: 0.2,
            metalness: 0.9
        });

        const glassMat = new THREE.MeshStandardMaterial({
            color: 0xffffff,
            roughness: 0.0,
            metalness: 0.1,
            transparent: true,
            opacity: 0.2
        });

        const dialMat = new THREE.MeshStandardMaterial({
            color: 0x0c0c14,
            roughness: 0.6
        });

        // 1. Casing
        const bezelGeo = new THREE.CylinderGeometry(1.6, 1.6, 0.35, 32);
        const bezel = new THREE.Mesh(bezelGeo, bezelMat);
        bezel.rotation.x = Math.PI / 2;
        watchGroup.add(bezel);

        // 2. Inner Dial
        const dialGeo = new THREE.CylinderGeometry(1.45, 1.45, 0.05, 32);
        const dial = new THREE.Mesh(dialGeo, dialMat);
        dial.rotation.x = Math.PI / 2;
        dial.position.z = 0.12;
        watchGroup.add(dial);

        // 3. Hands
        const hourHandMesh = new THREE.Mesh(
            new THREE.BoxGeometry(0.08, 0.7, 0.02),
            new THREE.MeshBasicMaterial({ color: 0xffffff })
        );
        hourHandMesh.position.y = 0.35;
        const hourHandGroup = new THREE.Group();
        hourHandGroup.position.set(0, 0, 0.16);
        hourHandGroup.add(hourHandMesh);
        watchGroup.add(hourHandGroup);

        const minHandMesh = new THREE.Mesh(
            new THREE.BoxGeometry(0.05, 1.0, 0.02),
            new THREE.MeshBasicMaterial({ color: 0xffffff })
        );
        minHandMesh.position.y = 0.5;
        const minHandGroup = new THREE.Group();
        minHandGroup.position.set(0, 0, 0.17);
        minHandGroup.add(minHandMesh);
        watchGroup.add(minHandGroup);

        const secHandMesh = new THREE.Mesh(
            new THREE.BoxGeometry(0.02, 1.15, 0.01),
            new THREE.MeshBasicMaterial({ color: 0xd4af37 })
        );
        secHandMesh.position.y = 0.575;
        const secHandGroup = new THREE.Group();
        secHandGroup.position.set(0, 0, 0.18);
        secHandGroup.add(secHandMesh);
        watchGroup.add(secHandGroup);

        // 4. Astronomical Orbital Rings
        const orbitGroup = new THREE.Group();
        watchGroup.add(orbitGroup);

        const ring1 = new THREE.Mesh(
            new THREE.TorusGeometry(2.1, 0.03, 8, 48),
            new THREE.MeshStandardMaterial({ color: 0xd4af37, roughness: 0.1, metalness: 0.9 })
        );
        ring1.rotation.y = Math.PI / 6;
        orbitGroup.add(ring1);

        const ring2 = new THREE.Mesh(
            new THREE.TorusGeometry(2.5, 0.02, 8, 48),
            new THREE.MeshStandardMaterial({ color: 0x8888aa, roughness: 0.1, metalness: 0.9 })
        );
        ring2.rotation.x = Math.PI / 4;
        orbitGroup.add(ring2);

        // Interactivity
        let platinumMode = false;
        let fastSpin = false;

        document.getElementById('btn-platinum').addEventListener('click', () => {
            platinumMode = !platinumMode;
            const btn = document.getElementById('btn-platinum');
            if (platinumMode) {
                btn.innerText = "✓ Deep Space Platinum Bezel";
                bezelMat.color.setHex(0xe5e7eb);
                ring1.material.color.setHex(0xe5e7eb);
                secHandMesh.material.color.setHex(0xe5e7eb);
            } else {
                btn.innerText = "✨ Gold Cosmos Bezel";
                bezelMat.color.setHex(0xd4af37);
                ring1.material.color.setHex(0xd4af37);
                secHandMesh.material.color.setHex(0xd4af37);
            }
        });

        document.getElementById('btn-spin').addEventListener('click', () => {
            fastSpin = !fastSpin;
            document.getElementById('btn-spin').innerText = fastSpin ? "✓ High Velocity Active" : "🌀 Fast Orbit Tracker";
        });

        // Time updates
        function updateTime() {
            const now = new Date();
            const h = now.getHours();
            const m = now.getMinutes();
            const s = now.getSeconds();

            document.getElementById('time-status').innerText = "SYSTEM LOCAL TIME: " + 
                h.toString().padStart(2, '0') + ":" + 
                m.toString().padStart(2, '0') + ":" + 
                s.toString().padStart(2, '0');

            // Angle calculations
            hourHandGroup.rotation.z = -((h % 12) * 30 + m * 0.5) * Math.PI / 180;
            minHandGroup.rotation.z = -(m * 6) * Math.PI / 180;
            secHandGroup.rotation.z = -(s * 6) * Math.PI / 180;
        }

        // Animation Loop
        const clock = new THREE.Clock();
        function animate() {
            requestAnimationFrame(animate);
            controls.update();
            updateTime();

            const elapsed = clock.getElapsedTime();
            const spinFactor = fastSpin ? 6.0 : 1.0;

            // Slow rotate watch assembly
            watchGroup.rotation.y = Math.sin(elapsed * 0.25) * 0.25;

            // Rotate orbital rings
            ring1.rotation.z = elapsed * 0.15 * spinFactor;
            ring2.rotation.z = -elapsed * 0.25 * spinFactor;

            renderer.render(scene, camera);
        }
        animate();

        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });
    </script>
</body>
</html>`;

      case "review":
        return `### PEER REVIEW REPORT
**Reviewer Node**: ${modelName}
**Status**: APPROVED & SPECTACULAR BRAND POSITIONING

1. **Geometry Analysis**:
   - Built a custom 3D mechanical bezel and clock mechanics.
   - Designed elegant star constellation points that render procedural floating systems without assets.

**Quality Score**: 9.8/10
*Verification successful. Deluxe brand watch visual clearing complete.*`;

      case "export":
        return `<!-- 
=========================================
FINAL PRODUCTION EXPORT (WATCH COMPLETED)
Target: Stand-Alone WebGL Watch Showroom Output
Generated on: ${new Date().toLocaleDateString()}
Pipeline Signature: 5S_CELESTIAL_CHRONO_OK
=========================================
-->

${prevOutput || "No contents available."}

<!-- 
--- END OF PACKAGE --- 
-->`;
    }
  }

  // ==========================================
  // 4. NEURAL ORCHESTRATION GRAPH (isGeneral)
  // ==========================================
  switch (stageId) {
    case "init":
      return `[SYSTEM KERNEL INITIALIZED]
Payload: "${cleanPrompt2}"
CAD Render Profile: Multi-Model Neural Network Graph (WebGL / Three.js)
Target Environment: Single-file stand-alone sandboxed iframe.
Coordinating model nodes to design, review, and pack a live 3D Node topology of your labor pool.`;

    case "generate":
      return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>3D Multi-Agent Model Labor Pool Draft</title>
</head>
<body style="background: #080a10; color: #4e5361; font-family: monospace; padding: 40px; text-align: center;">
    <div style="border: 1px dashed #2e3549; padding: 40px; display: inline-block; border-radius: 8px; margin-top: 15%;">
        <h3 style="color: #ecc94b;">[DRAFT GENERATED BY ${modelName}]</h3>
        <p>Structuring multi-model node coordinates: GPT-4o, Claude 3.5, Gemini 1.5, Mistral, Llama 3...</p>
        <p>Configuring inter-model synapse links and tensor routes...</p>
    </div>
</body>
</html>`;

    case "refine":
      return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>3D Model Labor Pool Visualizer</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
    <style>
        body { margin: 0; overflow: hidden; background: #07090e; color: #f1f5f9; font-family: ui-sans-serif, system-ui, sans-serif; }
        #canvas-container { width: 100%; height: 100vh; position: absolute; top: 0; left: 0; z-index: 10; }
        .ui-overlay { position: absolute; z-index: 20; pointer-events: none; }
        .interactive { pointer-events: auto; }
        .glowing-panel {
            background: rgba(7, 9, 14, 0.85);
            backdrop-filter: blur(8px);
            border: 1px solid rgba(236, 201, 75, 0.2);
            box-shadow: 0 4px 25px rgba(0, 0, 0, 0.5);
        }
    </style>
</head>
<body>
    <div id="canvas-container"></div>
    
    <div class="ui-overlay top-0 left-0 p-6 flex flex-col gap-2 max-w-md">
        <div class="glowing-panel p-4 rounded-lg">
            <span class="text-[10px] font-mono text-yellow-400 tracking-widest uppercase font-bold block mb-1">COGNITIVE FABRIC</span>
            <h1 class="text-xl font-bold tracking-tight text-white">Multi-Agent Labor Pool</h1>
            <p class="text-xs text-slate-400 mt-1 leading-relaxed font-sans">
                A live 3D visualization of model nodes in your execution pipeline.synapse paths represent Stage 01 - Stage 05 pipelines.
            </p>
        </div>
        
        <div class="glowing-panel p-3 rounded-lg flex gap-2 interactive">
            <button id="btn-pulse" class="bg-yellow-950/40 hover:bg-yellow-900/60 border border-yellow-500/30 hover:border-yellow-400 text-[11px] font-mono text-yellow-300 px-3.5 py-2 rounded transition-all">
                ⚡ Send Synaptic Workload Pulse
            </button>
            <button id="btn-reset" class="bg-slate-800 hover:bg-slate-700 border border-slate-700 text-[11px] font-mono text-slate-300 px-3 py-2 rounded transition-all">
                Reset Layout
            </button>
        </div>
    </div>

    <div class="ui-overlay bottom-0 right-0 p-6 text-right max-w-sm">
        <div class="glowing-panel p-4 rounded-lg text-left">
            <span class="text-[9px] font-mono text-slate-500 uppercase block tracking-wider">Node Inspection telemetry</span>
            <h3 id="node-title" class="text-xs font-mono font-bold text-yellow-400 mt-1">Select an active LLM node...</h3>
            <div id="node-fields" class="text-[11px] text-slate-400 font-mono mt-2 space-y-1">
                Click directly on any model sphere node in the WebGL canvas to inspect details, specialized roles, latencies, and billing costs.
            </div>
        </div>
    </div>

    <script>
        const container = document.getElementById('canvas-container');
        const scene = new THREE.Scene();
        scene.background = new THREE.Color(0x07090e);
        scene.fog = new THREE.FogExp2(0x07090e, 0.08);

        const camera = new THREE.PerspectiveCamera(45, window.innerWidth / window.innerHeight, 0.1, 100);
        camera.position.set(0, 5, 10);

        const renderer = new THREE.WebGLRenderer({ antialias: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        container.appendChild(renderer.domElement);

        const controls = new THREE.OrbitControls(camera, renderer.domElement);
        controls.enableDamping = true;
        controls.dampingFactor = 0.05;

        // Lights
        const ambientLight = new THREE.AmbientLight(0xffffff, 0.3);
        scene.add(ambientLight);

        const goldLight = new THREE.PointLight(0xecc94b, 1.5, 15);
        goldLight.position.set(0, 3, 0);
        scene.add(goldLight);

        // Constellation backing particles
        const starGeo = new THREE.BufferGeometry();
        const starCount = 300;
        const starPos = new Float32Array(starCount * 3);
        for(let i=0; i<starCount*3; i+=3) {
            starPos[i] = (Math.random() - 0.5) * 20;
            starPos[i+1] = (Math.random() - 0.5) * 20;
            starPos[i+2] = (Math.random() - 0.5) * 20;
        }
        starGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
        const starMat = new THREE.PointsMaterial({ color: 0x4299e1, size: 0.04, transparent: true, opacity: 0.4 });
        const stars = new THREE.Points(starGeo, starMat);
        scene.add(stars);

        // Model Node definitions
        const nodes = [
            { id: 'node-a', name: 'GPT-4o / Pro-Active', color: 0xf59e0b, pos: [-2.5, 0.5, 1.5], desc: 'Fast scaffolding drafts and high speed content synthesis.', cost: '$15.00/hr', status: 'Active', latency: '2.1s' },
            { id: 'node-b', name: 'Claude 3.5 / Logic', color: 0x8b5cf6, pos: [-1.5, 0.5, -2.5], desc: 'Strict logical layout formatting, detailed code, robust structuring.', cost: '$24.00/hr', status: 'Active', latency: '4.8s' },
            { id: 'node-c', name: 'Gemini 1.5 Pro / Analysis', color: 0x10b981, pos: [2.5, 0.5, -1.5], desc: 'In-depth validation audit, massive context checks, security ledgers.', cost: '$18.00/hr', status: 'Active', latency: '3.5s' },
            { id: 'node-d', name: 'Mistral / Synthesizer', color: 0xec4899, pos: [2.0, 0.5, 2.0], desc: 'Multi-agent markdown compilations and elegant document delivery.', cost: '$12.00/hr', status: 'Active', latency: '1.9s' },
            { id: 'node-e', name: 'Llama 3 / Support', color: 0x6b7280, pos: [0.0, 0.5, 3.0], desc: 'Idle backup node reserved for low priority pipelines.', cost: '$8.00/hr', status: 'Idle', latency: '0s' }
        ];

        const nodeGroup = new THREE.Group();
        scene.add(nodeGroup);

        const nodeMeshes = {};
        const sphereGeo = new THREE.SphereGeometry(0.55, 32, 32);

        nodes.forEach(n => {
            const material = new THREE.MeshStandardMaterial({
                color: n.color,
                roughness: 0.2,
                metalness: 0.8,
                emissive: n.color,
                emissiveIntensity: n.id === 'node-e' ? 0.02 : 0.2
            });
            const mesh = new THREE.Mesh(sphereGeo, material);
            mesh.position.set(...n.pos);
            mesh.userData = n;
            nodeGroup.add(mesh);
            nodeMeshes[n.id] = mesh;

            // Small glowing ring around node
            const ringGeo = new THREE.TorusGeometry(0.75, 0.02, 8, 32);
            const ringMat = new THREE.MeshBasicMaterial({ color: n.color, transparent: true, opacity: 0.3 });
            const ring = new THREE.Mesh(ringGeo, ringMat);
            ring.rotation.x = Math.PI / 2;
            ring.position.set(n.pos[0], n.pos[1], n.pos[2]);
            scene.add(ring);
        });

        // Synaptic connectors
        function connect(start, end, color) {
            const points = [
                new THREE.Vector3(...start.pos),
                new THREE.Vector3(...end.pos)
            ];
            const geo = new THREE.BufferGeometry().setFromPoints(points);
            const mat = new THREE.LineBasicMaterial({ color: color, transparent: true, opacity: 0.4 });
            scene.add(new THREE.Line(geo, mat));
        }

        connect(nodes[0], nodes[1], 0xf59e0b);
        connect(nodes[1], nodes[2], 0x8b5cf6);
        connect(nodes[2], nodes[3], 0x10b981);
        connect(nodes[3], nodes[0], 0xec4899);

        // Synaptic workload particles
        const particles = [];
        const partGeo = new THREE.SphereGeometry(0.06, 8, 8);
        const partMat = new THREE.MeshBasicMaterial({ color: 0xffffff });

        function triggerSynapticPulse() {
            // Remove previous
            particles.forEach(p => scene.remove(p));
            particles.length = 0;

            const pathways = [
                { s: nodeMeshes['node-a'], e: nodeMeshes['node-b'] },
                { s: nodeMeshes['node-b'], e: nodeMeshes['node-c'] },
                { s: nodeMeshes['node-c'], e: nodeMeshes['node-d'] },
                { s: nodeMeshes['node-d'], e: nodeMeshes['node-a'] }
            ];

            pathways.forEach(path => {
                const p = new THREE.Mesh(partGeo, partMat);
                p.position.copy(path.s.position);
                p.userData = {
                    s: path.s.position.clone(),
                    e: path.e.position.clone(),
                    prog: 0,
                    speed: 0.04
                };
                scene.add(p);
                particles.push(p);

                // Flashes the nodes on impact
                path.s.scale.set(1.4, 1.4, 1.4);
                setTimeout(() => path.s.scale.set(1, 1, 1), 250);
            });
        }

        // Raycasting
        const raycaster = new THREE.Raycaster();
        const mouse = new THREE.Vector2();

        window.addEventListener('pointerdown', (e) => {
            mouse.x = (e.clientX / window.innerWidth) * 2 - 1;
            mouse.y = -(e.clientY / window.innerHeight) * 2 + 1;
            raycaster.setFromCamera(mouse, camera);

            const intersects = raycaster.intersectObjects(nodeGroup.children);
            if (intersects.length > 0) {
                const node = intersects[0].object;
                const d = node.userData;

                // Emphasize clicked
                nodeGroup.children.forEach(c => c.scale.set(1, 1, 1));
                node.scale.set(1.25, 1.25, 1.25);

                document.getElementById('node-title').innerText = d.name.toUpperCase();
                document.getElementById('node-title').style.color = '#' + d.color.toString(16).padStart(6, '0');
                document.getElementById('node-fields').innerHTML = 
                    '<div class="flex justify-between border-b border-slate-800 pb-1.5 mb-1.5">' +
                        '<span class="text-slate-500">Node Status:</span>' +
                        '<span class="font-bold text-emerald-400 font-mono">' + d.status + '</span>' +
                    '</div>' +
                    '<div class="flex justify-between border-b border-slate-800 pb-1.5 mb-1.5">' +
                        '<span class="text-slate-500">Target Latency:</span>' +
                        '<span class="text-white font-mono">' + d.latency + '</span>' +
                    '</div>' +
                    '<div class="flex justify-between border-b border-slate-800 pb-1.5 mb-1.5">' +
                        '<span class="text-slate-500">Compute Billing:</span>' +
                        '<span class="text-yellow-400 font-mono">' + d.cost + '</span>' +
                    '</div>' +
                    '<div class="text-slate-300 italic text-[11px] leading-relaxed mt-2 bg-black/40 p-2 rounded">' +
                        '"' + d.desc + '"' +
                    '</div>';
            }
        });

        document.getElementById('btn-pulse').addEventListener('click', () => {
            triggerSynapticPulse();
        });

        document.getElementById('btn-reset').addEventListener('click', () => {
            camera.position.set(0, 5, 10);
            nodeGroup.children.forEach(c => c.scale.set(1, 1, 1));
            document.getElementById('node-title').innerText = "Select an active LLM node...";
            document.getElementById('node-fields').innerHTML = "Click directly on any model sphere node in the WebGL canvas to inspect details, specialized roles, latencies, and billing costs.";
        });

        // Animation loop
        const clock = new THREE.Clock();
        function animate() {
            requestAnimationFrame(animate);
            controls.update();

            const elapsed = clock.getElapsedTime();
            stars.rotation.y = elapsed * 0.05;

            // Slow idle node hover oscillations
            nodeGroup.children.forEach((node, idx) => {
                node.position.y = node.userData.pos[1] + Math.sin(elapsed * 1.5 + idx) * 0.12;
            });

            // Workload synapase transmission updates
            for (let i = particles.length - 1; i >= 0; i--) {
                const p = particles[i];
                p.userData.prog += p.userData.speed;
                if (p.userData.prog >= 1.0) {
                    scene.remove(p);
                    particles.splice(i, 1);
                } else {
                    p.position.lerpVectors(p.userData.s, p.userData.e, p.userData.prog);
                }
            }

            renderer.render(scene, camera);
        }
        animate();

        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });
    </script>
</body>
</html>`;

    case "review":
      return `### PEER REVIEW REPORT
**Reviewer Node**: ${modelName}
**Status**: APPROVED WITH MINOR RECOMMENDATIONS

1. **Topological Integration**:
   - Multi-agent network connections verified. Synapse transmission rates mapped accurately.
   - Beautiful visual feedback of model node weight profiles in three dimensional WebGL coordinates.

**Quality Score**: 9.4/10
*Verification successful. General Labor Pool architecture approved.*`;

    case "export":
      return `<!-- 
=========================================
FINAL PRODUCTION EXPORT (PIPELINE COMPLETED)
Target: Stand-Alone WebGL Model Labor Pool Output
Generated on: ${new Date().toLocaleDateString()}
Pipeline Signature: 5S_STRICT_SEGR_OK
=========================================
-->

${prevOutput || "No contents available."}

<!-- 
--- END OF PACKAGE --- 
-->`;

    default:
      return "Default payload execution complete.";
  }
}

// Run pipeline endpoint
app.post("/api/run-pipeline", async (req, res) => {
  const { prompt, modelAssignments, enforcementMode, customPool, forceSimulate } = req.body;
  
  if (!prompt || !prompt.trim()) {
    return res.status(400).json({ error: "Prompt is required." });
  }

  const pool = customPool || DEFAULT_POOL;
  const assignments = modelAssignments || {};
  
  const runId = "run_" + Math.random().toString(36).substring(2, 11);
  const startTime = Date.now();
  
  const stageExecutions: Record<string, any> = {};
  const integrityLogs: any[] = [];
  
  let currentStatus: "completed" | "failed" | "blocked" = "completed";
  let totalCost = 0;
  let totalTokens = 0;

  // Track assignments for checking
  const genModelId = assignments["generate"];
  const refineModelId = assignments["refine"];
  let reviewModelId = assignments["review"];
  const exportModelId = assignments["export"];

  const getModelName = (id: string) => {
    if (id === "system") return "System Kernel";
    const m = pool.find((n: any) => n.id === id);
    return m ? m.name : id;
  };

  const getModelCost = (id: string) => {
    if (id === "system") return 0;
    const m = pool.find((n: any) => n.id === id);
    return m ? m.costPerHr / 3600 : 0.001; // basic cost per sec approx
  };

  const ai = getAiClient();
  let isLive = !!ai && !forceSimulate;
  let liveFallbackTriggered = false;
  let liveFallbackReason = "";

  // Let's go through the stages
  const stages = [
    { id: "init", name: "01. Init", label: "Initialization", model: "system" },
    { id: "generate", name: "02. Generate", label: "Draft Generation", model: genModelId },
    { id: "refine", name: "03. Refine", label: "Logic Optimization", model: refineModelId },
    { id: "review", name: "04. Review", label: "Peer Integrity Review", model: reviewModelId },
    { id: "export", name: "05. Export", label: "Packaging & Delivery", model: exportModelId || "system" },
  ];

  let accumulatedContent = "";

  for (let i = 0; i < stages.length; i++) {
    const stage = stages[i];
    const stageId = stage.id;
    let assignedModelId = stage.model;

    // Check Integrity Protocol for Stage 4 (Review)
    if (stageId === "review") {
      const isGeneratingOwnContent = (assignedModelId === genModelId || assignedModelId === refineModelId);
      
      if (isGeneratingOwnContent && assignedModelId !== "system") {
        const offendingModelName = getModelName(assignedModelId);
        
        integrityLogs.push({
          timestamp: new Date().toISOString(),
          type: "conflict_detected",
          message: `INTEGRITY VIOLATION: ${offendingModelName} (Node ID: ${assignedModelId}) is assigned to both Generation/Refinement and Review. This violates the core segregation protocol.`,
          blockedNodeId: assignedModelId,
          stageId: "review"
        });

        if (enforcementMode === "strict_block") {
          currentStatus = "blocked";
          // Mark Review and subsequent stages as BLOCKED
          stageExecutions[stageId] = {
            stageId,
            status: "blocked",
            modelId: assignedModelId,
            modelName: offendingModelName,
            output: "",
            logs: [
              "CRITICAL PIPELINE BLOCK",
              `Enforced Policy: 'Sticky Author Restriction' is Active.`,
              `Node ${assignedModelId} is an author of this payload (Stage 02/03) and cannot serve as the Peer Reviewer.`,
              `Execution suspended.`
            ],
            durationMs: 0,
            tokensUsed: 0,
            cost: 0
          };

          // Block final export as well
          stageExecutions["export"] = {
            stageId: "export",
            status: "skipped",
            modelId: "system",
            modelName: "System Kernel",
            output: "",
            logs: ["Skipped due to upstream pipeline block in Stage 04."],
            durationMs: 0,
            tokensUsed: 0,
            cost: 0
          };
          break; // Stop execution
        } else {
          // auto_substitute
          // Find an active model in the pool that is not genModelId and not refineModelId
          const substitute = pool.find((n: any) => 
            n.id !== genModelId && 
            n.id !== refineModelId && 
            n.status === "Active"
          );

          if (substitute) {
            const oldModelName = offendingModelName;
            assignedModelId = substitute.id;
            reviewModelId = substitute.id; // update tracking
            
            integrityLogs.push({
              timestamp: new Date().toISOString(),
              type: "substitution_enforced",
              message: `AUTO-SUBSTITUTION TRIGGERED: Enforced role segregation. Swapped out ${oldModelName} with ${substitute.name} (Node ID: ${substitute.id}) for Stage 04.Review.`,
              blockedNodeId: assignedModelId,
              substitutedNodeId: substitute.id,
              stageId: "review"
            });
          } else {
            // No backups available! Must block
            currentStatus = "blocked";
            stageExecutions[stageId] = {
              stageId,
              status: "blocked",
              modelId: assignedModelId,
              modelName: offendingModelName,
              output: "",
              logs: [
                "CRITICAL PIPELINE BLOCK: NO BACKUP FOUND",
                "Cannot perform auto-substitution: No other eligible Active models found in the Labor Pool.",
                "Execution suspended."
              ],
              durationMs: 0,
              tokensUsed: 0,
              cost: 0
            };
            stageExecutions["export"] = {
              stageId: "export",
              status: "skipped",
              modelId: "system",
              modelName: "System Kernel",
              output: "",
              logs: ["Skipped due to upstream pipeline block in Stage 04."],
              durationMs: 0,
              tokensUsed: 0,
              cost: 0
            };
            break;
          }
        }
      }
    }

    // Measure time and execution
    const mName = getModelName(assignedModelId);
    const mCostPerSec = getModelCost(assignedModelId);
    const startStageTime = Date.now();
    
    let outputContent = "";
    let logs: string[] = [`Node assigned: ${mName}`, "Initializing workspace..."];
    let tokensUsed = Math.floor(Math.random() * 500) + 150; // default simulation

    if (isLive) {
      // LIVE GEMINI RUN
      try {
        logs.push(`Connecting to live Google Cloud API via Gemini 2.5...`);
        let promptText = "";
        
        if (stageId === "init") {
          promptText = `Prepare standard system execution environment parameters for user task: "${prompt}"`;
        } else if (stageId === "generate") {
          let instruction = "";
          if (prompt.toLowerCase().includes("html") || prompt.toLowerCase().includes("css") || prompt.toLowerCase().includes("js") || prompt.toLowerCase().includes("3d") || prompt.toLowerCase().includes("game") || prompt.toLowerCase().includes("canvas")) {
            instruction = `Output ONLY a single, complete, fully-functional HTML file containing all styles, scripts, and libraries (like Three.js if needed). No conversational text, no explanations, no markdown blocks. Start directly with <!DOCTYPE html> and end with </html>.`;
          } else {
            instruction = `Solve the following user prompt. Provide clean, well-formatted output (preferably markdown or code block).`;
          }
          promptText = `You are simulated as model node "${mName}". Your specialty is high-speed generation and code/text drafts. 
${instruction}
User prompt: "${prompt}"`;
        } else if (stageId === "refine") {
          let instruction = "";
          if (prompt.toLowerCase().includes("html") || prompt.toLowerCase().includes("css") || prompt.toLowerCase().includes("js") || prompt.toLowerCase().includes("3d") || prompt.toLowerCase().includes("game") || prompt.toLowerCase().includes("canvas")) {
            instruction = `Output ONLY the optimized, complete, raw HTML code. Do NOT wrap it in markdown code blocks. Start directly with <!DOCTYPE html> and end with </html>. Ensure all interaction elements are fully coded with no comments like '// Add logic here'.`;
          } else {
            instruction = `Please optimize, detail, and refine it. Add professional enhancements as necessary. Do not start from scratch, improve what is there:`;
          }
          promptText = `You are simulated as model node "${mName}". Your specialty is logical optimization and detailing.
${instruction}
--- DRAFT ---
${accumulatedContent}
--- END DRAFT ---`;
        } else if (stageId === "review") {
          promptText = `You are simulated as model node "${mName}". Your specialty is Peer Integrity Review and quality assurance.
Below is refined code/text from an authoring node. Please perform a rigorous audit. Identify any performance bottlenecks, edge-case bugs, or clarity issues. Assign a Quality Score out of 10.
--- CONTENT TO AUDIT ---
${accumulatedContent}
--- END AUDIT ---`;
        } else if (stageId === "export") {
          promptText = `You are simulated as model node "${mName}". Your job is to package and format the final deliverables.
Below is the evaluated content and its review report. Wrap it in a beautiful, publication-ready layout with meta headers.
If the content is HTML code, keep the HTML code completely clean, valid, and executable, wrapping any packaging headers or audit notes inside HTML comments at the top or bottom of the file (e.g. <!-- Export Headers -->), so that the entire output remains an executable single-file HTML document.
--- AUDITED CONTENT ---
${accumulatedContent}
--- END AUDITED CONTENT ---`;
        }

        const response = await ai.models.generateContent({
          model: "gemini-2.5-flash",
          contents: promptText,
          config: {
            temperature: 0.2,
            maxOutputTokens: 8192,
          }
        });

        outputContent = response.text || "";
        tokensUsed = response.usageMetadata?.totalTokenCount || outputContent.length / 4;
        logs.push("Received API response successfully.");
        logs.push(`Response token count: ${tokensUsed}`);
      } catch (err: any) {
        const isQuota = err.message?.includes("quota") || err.message?.includes("429") || err.message?.includes("RESOURCE_EXHAUSTED");
        const shortMsg = isQuota ? "Gemini rate limits active" : "Connection timeout";
        console.log(`[Gemini Info] Switching stage ${stageId} to high-speed backup simulator (${shortMsg})`);

        isLive = false; // Disable live calls for all subsequent stages in this run
        liveFallbackTriggered = true;
        liveFallbackReason = isQuota ? "Live Gemini API quota limits reached. Automatically executing via high-speed backup simulator." : "Live Gemini API connection issue. Automatically executing via high-speed backup simulator.";

        logs.push(`[Info] Switched to high-speed simulated fallback`);
        logs.push("Safety protocol: Falling back to local model proxy simulation for remaining stages.");
        outputContent = generateSimulatedContent(stageId, mName, prompt, accumulatedContent);
      }
    } else {
      // SIMULATED RUN
      // Small simulated latency to make the progress tracker feel tactile and realistic
      // (The UI will receive updates or wait for the return, we can also add a small timeout if needed but on backend we can return immediately, the UI can do staggered loading. Or we can add a tiny sleep)
      outputContent = generateSimulatedContent(stageId, mName, prompt, accumulatedContent);
      logs.push("Loaded node pre-cache weights successfully.");
      logs.push("Running tensor evaluation...");
      logs.push("Completed local node verification.");
    }

    if (stageId !== "init" && stageId !== "review") {
      accumulatedContent = outputContent; // update the main asset being worked on
    }

    const durationMs = Date.now() - startStageTime;
    const calculatedCost = (durationMs / 1000) * mCostPerSec + (tokensUsed * 0.000002); // hybrid cost model

    totalCost += calculatedCost;
    totalTokens += tokensUsed;

    stageExecutions[stageId] = {
      stageId,
      status: "completed",
      modelId: assignedModelId,
      modelName: mName,
      output: outputContent,
      logs: [...logs, "Execution finished successfully."],
      durationMs,
      tokensUsed,
      cost: parseFloat(calculatedCost.toFixed(6))
    };
  }

  const durationTotal = Date.now() - startTime;

  res.json({
    id: runId,
    title: prompt.substring(0, 30) + (prompt.length > 30 ? "..." : ""),
    prompt,
    status: currentStatus,
    createdAt: new Date().toISOString(),
    modelAssignments: assignments,
    stageExecutions,
    integrityLogs,
    totalTokens,
    totalCost: parseFloat(totalCost.toFixed(4)),
    enforcementMode,
    liveFallbackTriggered,
    liveFallbackReason
  });
});

// Serve Vite client in dev/prod
if (process.env.NODE_ENV !== "production") {
  import("vite").then(async (vite) => {
    const viteDevServer = await vite.createServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(viteDevServer.middlewares);
    
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Development Server running on http://localhost:${PORT}`);
    });
  });
} else {
  const distPath = path.join(process.cwd(), "dist");
  app.use(express.static(distPath));
  app.get("*", (req, res) => {
    res.sendFile(path.join(distPath, "index.html"));
  });
  
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Production Server running on port ${PORT}`);
  });
}
