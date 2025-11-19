// Solar System (p5.js)
// Paste into editor.p5js.org as sketch.js

let planets = [];
let sun;
let paused = false;
let showTrails = true;
let trailLength = 200;
let scaleFactor = 1.0;
let panX = 0, panY = 0;
let dragging = false;
let lastMouseX = 0, lastMouseY = 0;
let infoVisible = true;

function setup() {
  createCanvas(windowWidth, windowHeight);
  angleMode(RADIANS);
  textFont('Arial');

  // Sun (center)
  sun = {
    name: 'Sun',
    radius: 30,
    color: [255, 200, 50],
    x: 0,
    y: 0
  };

  // Planets: name, distance (AU-ish relative), radius (visual), color, period (seconds for one orbit), initial angle, moons
  // Distances and radii are scaled for visibility — not to real-world scale.
  planets = [
    { name: 'Mercury', d: 60, r: 4, color: [169,169,169], period: 8, angle: random(TWO_PI), trail: [], moons: [] },
    { name: 'Venus',   d: 95, r: 7, color: [240,200,136], period: 20, angle: random(TWO_PI), trail: [], moons: [] },
    { name: 'Earth',   d: 140, r: 8, color: [80,150,255], period: 30, angle: random(TWO_PI), trail: [], moons:
        [ { name: 'Moon', d: 18, r: 2, color: [200,200,200], period: 4, angle: random(TWO_PI), trail: [] } ] },
    { name: 'Mars',    d: 185, r: 6, color: [200,100,80], period: 56, angle: random(TWO_PI), trail: [], moons: [] },
    { name: 'Jupiter', d: 260, r: 18, color: [210,160,110], period: 360, angle: random(TWO_PI), trail: [], moons: [] },
    { name: 'Saturn',  d: 340, r: 16, color: [235,210,150], period: 700, angle: random(TWO_PI), trail: [], moons:
        [ { name: 'Titan', d: 30, r: 3, color: [220,180,120], period: 20, angle: random(TWO_PI), trail: [] } ] },
    { name: 'Uranus',  d: 420, r: 12, color: [170,220,230], period: 2200, angle: random(TWO_PI), trail: [], moons: [] },
    { name: 'Neptune', d: 480, r: 12, color: [100,150,255], period: 4200, angle: random(TWO_PI), trail: [], moons: [] }
  ];

  // Fit view: center at canvas center
  panX = width / 2;
  panY = height / 2;
}

function windowResized() {
  resizeCanvas(windowWidth, windowHeight);
  if (!dragging) {
    panX = width / 2;
    panY = height / 2;
  }
}

function draw() {
  background(8, 12, 20);
  push();
  // apply pan & zoom
  translate(panX, panY);
  scale(scaleFactor);

  // starfield background (parallax)
  drawStars();

  // draw orbits
  noFill();
  stroke(100, 60);
  strokeWeight(1 / max(scaleFactor, 0.01));
  for (let p of planets) {
    ellipse(0, 0, p.d * 2, p.d * 2);
  }

  // draw sun
  drawSun();

  // update & draw planets and moons
  for (let p of planets) {
    updatePlanet(p);
    drawPlanetWithMoons(p);
  }

  pop();

  // UI overlay
  drawUI();
}

function drawSun() {
  noStroke();
  // glowing
  for (let i = 6; i >= 1; i--) {
    let a = map(i, 6, 1, 6, 20);
    fill(sun.color[0], sun.color[1], sun.color[2], a * 12);
    ellipse(0, 0, (sun.radius + i * 30));
  }
  fill(...sun.color);
  ellipse(0, 0, sun.radius * 2);
}

function updatePlanet(p) {
  if (!paused) {
    let angularSpeed = TWO_PI / p.period; // radians per second of our simulated time
    p.angle += angularSpeed * (deltaTime / 1000.0); // deltaTime in ms
  }

  // compute position
  p.x = cos(p.angle) * p.d;
  p.y = sin(p.angle) * p.d;

  // trails: push current position
  if (showTrails) {
    p.trail = p.trail || [];
    p.trail.push({ x: p.x, y: p.y });
    if (p.trail.length > trailLength) p.trail.shift();
  } else {
    p.trail = [];
  }

  // update moons
  if (p.moons && p.moons.length) {
    for (let m of p.moons) {
      if (!paused) {
        let mSpeed = TWO_PI / m.period;
        m.angle += mSpeed * (deltaTime / 1000.0);
      }
      m.x = p.x + cos(m.angle) * m.d;
      m.y = p.y + sin(m.angle) * m.d;

      if (showTrails) {
        m.trail = m.trail || [];
        m.trail.push({ x: m.x, y: m.y });
        if (m.trail.length > trailLength) m.trail.shift();
      } else {
        m.trail = [];
      }
    }
  }
}

function drawPlanetWithMoons(p) {
  // trail
  if (showTrails && p.trail && p.trail.length > 1) {
    noFill();
    stroke(...p.color, 100);
    strokeWeight(1 / max(scaleFactor, 0.01));
    beginShape();
    for (let pt of p.trail) vertex(pt.x, pt.y);
    endShape();
  }

  // planet
  noStroke();
  fill(...p.color);
  ellipse(p.x, p.y, p.r * 2);

  // label
  push();
  let labelScale = 1 / max(scaleFactor, 0.01);
  scale(labelScale);
  fill(255);
  textSize(12);
  textAlign(CENTER);
  text(p.name, p.x * max(scaleFactor, 0.01), (p.y * max(scaleFactor, 0.01)) + p.r * 4);
  pop();

  // draw moons
  if (p.moons && p.moons.length) {
    for (let m of p.moons) {
      // moon trail
      if (showTrails && m.trail && m.trail.length > 1) {
        noFill();
        stroke(...m.color, 140);
        strokeWeight(0.8 / max(scaleFactor, 0.01));
        beginShape();
        for (let pt of m.trail) vertex(pt.x, pt.y);
        endShape();
      }
      fill(...m.color);
      noStroke();
      ellipse(m.x, m.y, m.r * 2);
    }
  }
}

function drawUI() {
  noStroke();
  fill(255);
  textSize(13);
  textAlign(LEFT, TOP);
  let lines = [
    "Solar System demo — Controls:",
    "Space: Pause/Resume   T: Toggle trails   I: Toggle info panel",
    "Mouse drag: Pan      Mouse wheel: Zoom    +/- : Zoom in/out",
    `Trails: ${showTrails ? 'ON' : 'OFF'}   Paused: ${paused ? 'YES' : 'NO'}`
  ];
  for (let i = 0; i < lines.length; i++) text(lines[i], 10, 10 + i * 18);

  if (infoVisible) {
    // small legend on right
    push();
    let boxW = 220;
    let boxH = 220;
    fill(0, 120);
    rect(width - boxW - 10, 10, boxW, boxH, 8);
    fill(255);
    textSize(12);
    textAlign(LEFT, TOP);
    text("Planets (visual scale):", width - boxW, 18);
    let y = 40;
    for (let p of planets) {
      fill(...p.color);
      ellipse(width - boxW + 12, y + 6, 10);
      fill(255);
      text(`${p.name}  dist:${p.d}  gap:${p.r}`, width - boxW + 28, y - 4);
      y += 22;
    }
    pop();
  }
}

// Mouse & keyboard interactions
function keyPressed() {
  if (key === ' ') {
    paused = !paused;
  } else if (key === 'T' || key === 't') {
    showTrails = !showTrails;
  } else if (key === 'I' || key === 'i') {
    infoVisible = !infoVisible;
  } else if (key === '+' || key === '=') {
    scaleFactor *= 1.15;
  } else if (key === '-') {
    scaleFactor /= 1.15;
  } else if (key === '0') {
    // reset view
    scaleFactor = 1.0;
    panX = width / 2;
    panY = height / 2;
  }
}

function mousePressed() {
  if (mouseButton === LEFT) {
    dragging = true;
    lastMouseX = mouseX;
    lastMouseY = mouseY;
  }
}

function mouseReleased() {
  dragging = false;
}

function mouseDragged() {
  if (dragging) {
    panX += mouseX - lastMouseX;
    panY += mouseY - lastMouseY;
    lastMouseX = mouseX;
    lastMouseY = mouseY;
  }
}

function mouseWheel(event) {
  // zoom centered on mouse
  let zoom = 1 - event.delta * 0.001;
  let newScale = scaleFactor * zoom;
  newScale = constrain(newScale, 0.2, 10);

  // adjust pan so zoom is focused at mouse point
  let wx = (mouseX - panX) / scaleFactor;
  let wy = (mouseY - panY) / scaleFactor;
  panX = mouseX - wx * newScale;
  panY = mouseY - wy * newScale;

  scaleFactor = newScale;
  return false; // prevent page scroll
}

function drawStars() {
  // subtle static starfield based on seed
  noStroke();
  fill(255, 255, 255, 120);
  let seed = 98765;
  randomSeed(seed);
  let count = 120;
  for (let i = 0; i < count; i++) {
    let sx = random(-width, width);
    let sy = random(-height, height);
    let sz = random(0.5, 2.4);
    ellipse(sx * 0.8, sy * 0.6, sz, sz);
  }
}
