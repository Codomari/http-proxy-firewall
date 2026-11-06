(() => {
  "use strict";
  const byId = id => document.getElementById(id);
  const messages = window.pfStatusLanguage.messages;
  const status = byId("restart-status"), continueButton = byId("restart-continue");
  const gameStatus = byId("game-status"), againButton = byId("game-again");
  const boardSize = 12, winLength = 5, storageKey = "pf-restart-game";
  const lines = [], linesByCell = Array.from({length: boardSize * boardSize}, () => []);
  for (let row = 0; row < boardSize; row++) {
    for (let column = 0; column < boardSize; column++) {
      for (const [dr, dc] of [[0,1], [1,0], [1,1], [1,-1]]) {
        const endRow = row + dr * (winLength - 1), endColumn = column + dc * (winLength - 1);
        if (endRow >= boardSize || endColumn < 0 || endColumn >= boardSize) continue;
        const line = Array.from({length: winLength}, (_, step) => (row + dr * step) * boardSize + column + dc * step);
        lines.push(line);
        line.forEach(index => linesByCell[index].push(line));
      }
    }
  }
  let checking = false, navigating = false, ready = false, gameStarted = false;
  let board = Array(boardSize * boardSize).fill(""), computerTurn = false, gameOver = false;
  let gameOutcome = "", computerTimer = null;
  const cells = board.map((_, index) => {
    const cell = document.createElement("button");
    cell.type = "button";
    cell.addEventListener("click", () => play(index));
    byId("game-board").appendChild(cell);
    return cell;
  });
  byId("restart-game").hidden = false;
  byId("restart-card").classList.add("with-game");

  function navigate() {
    if (navigating) return;
    navigating = true;
    status.textContent = messages.ready;
    // Location navigation always uses GET, including after an interrupted form.
    window.location.replace(window.location.href);
  }
  continueButton.addEventListener("click", navigate);

  function renderBoard() {
    cells.forEach((cell, index) => {
      const label = messages.cell_label.replace("{row}", String(Math.floor(index / boardSize) + 1)).replace("{column}", String(index % boardSize + 1));
      cell.textContent = board[index];
      cell.disabled = computerTurn || gameOver || board[index] !== "";
      cell.setAttribute("aria-label", board[index] ? `${label}: ${board[index]}` : label);
    });
    gameStatus.textContent = gameOutcome ? messages[gameOutcome] : computerTurn ? messages.computer_turn : messages.your_turn;
    againButton.hidden = !gameOver;
  }
  function winner(mark, position = board) { return lines.some(line => line.every(index => position[index] === mark)); }
  function saveGame() {
    try {
      window.localStorage.setItem(storageKey, JSON.stringify({version: 1, size: boardSize, win_length: winLength, board, started: gameStarted}));
    } catch (_) { /* The game remains playable when storage is disabled or full. */ }
  }
  function restoreGame() {
    try {
      const data = window.localStorage.getItem(storageKey);
      if (!data || data.length > 4096) return;
      const saved = JSON.parse(data);
      if (!saved || saved.version !== 1 || saved.size !== boardSize || saved.win_length !== winLength || typeof saved.started !== "boolean" || !Array.isArray(saved.board) || saved.board.length !== board.length || !saved.board.every(value => value === "" || value === "X" || value === "O")) return;
      const xs = saved.board.filter(value => value === "X").length, os = saved.board.filter(value => value === "O").length;
      const xWins = winner("X", saved.board), oWins = winner("O", saved.board);
      if (os > xs || xs > os + 1 || xWins && oWins || xWins && xs !== os + 1 || oWins && xs !== os) return;
      board = saved.board.slice();
      gameStarted = saved.started || xs > 0;
      gameOutcome = xWins ? "win" : oWins ? "lose" : board.every(Boolean) ? "draw" : "";
      gameOver = gameOutcome !== "";
      computerTurn = !gameOver && xs > os;
    } catch (_) { /* Ignore malformed, outdated or inaccessible saved games. */ }
  }
  function finishRound() {
    gameOutcome = winner("X") ? "win" : winner("O") ? "lose" : board.every(Boolean) ? "draw" : "";
    gameOver = gameOutcome !== "";
    return gameOver;
  }
  function winningMove(mark) {
    for (const line of lines) {
      const empty = line.filter(index => board[index] === "");
      if (empty.length === 1 && line.every(index => board[index] === "" || board[index] === mark)) return empty[0];
    }
  }
  function moveScore(index, mark) {
    return linesByCell[index].reduce((score, line) => {
      if (line.some(position => board[position] !== "" && board[position] !== mark)) return score;
      return score + 6 ** line.filter(position => board[position] === mark).length;
    }, 0);
  }
  function computerMove() {
    if (!computerTurn || gameOver) return;
    const empty = board.map((value, index) => value ? -1 : index).filter(index => index >= 0);
    let chosen = winningMove("O");
    if (chosen === undefined) chosen = winningMove("X");
    if (chosen === undefined) {
      let best = -Infinity, candidates = [];
      for (const index of empty) {
        const distance = Math.abs(Math.floor(index / boardSize) - (boardSize - 1) / 2) + Math.abs(index % boardSize - (boardSize - 1) / 2);
        const score = moveScore(index, "O") + moveScore(index, "X") * 1.1 - distance * 0.01;
        if (score > best) { best = score; candidates = [index]; }
        else if (score === best) candidates.push(index);
      }
      chosen = candidates[Math.floor(Math.random() * candidates.length)];
    }
    if (chosen === undefined) return;
    board[chosen] = "O";
    computerTurn = false;
    finishRound();
    saveGame();
    renderBoard();
  }
  function scheduleComputer() {
    clearTimeout(computerTimer);
    computerTimer = setTimeout(() => { computerTimer = null; computerMove(); }, 200);
  }
  function play(index) {
    if (computerTurn || gameOver || board[index]) return;
    gameStarted = true;
    board[index] = "X";
    if (!finishRound()) { computerTurn = true; scheduleComputer(); }
    saveGame();
    renderBoard();
  }
  function restartGame() {
    clearTimeout(computerTimer);
    computerTimer = null;
    board = Array(boardSize * boardSize).fill("");
    gameOver = false;
    computerTurn = false;
    gameOutcome = "";
    gameStarted = true;
    saveGame();
    renderBoard();
    cells[0].focus();
  }
  againButton.addEventListener("click", restartGame);
  byId("game-restart").addEventListener("click", restartGame);
  document.addEventListener("pf-status-language-change", () => {
    status.textContent = navigating ? messages.ready : ready && gameStarted ? messages.ready_playing : messages.reconnecting;
    renderBoard();
  });

  async function retry() {
    if (checking || navigating || ready) return;
    checking = true;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2500);
    try {
      const response = await fetch(window.location.href, {method: "HEAD", cache: "no-store", credentials: "same-origin", redirect: "manual", signal: controller.signal});
      if (response.type === "opaqueredirect" || response.status >= 200 && response.status < 400) {
        ready = true;
        document.querySelector(".request-animation").hidden = true;
        if (gameStarted) {
          status.textContent = messages.ready_playing;
          continueButton.hidden = false;
        } else navigate();
      }
    } catch (_) {
      // The listener may be closed until the new process has started.
    } finally {
      clearTimeout(timeout);
      checking = false;
      if (!ready && !navigating) setTimeout(retry, 1000);
    }
  }

  restoreGame();
  renderBoard();
  if (computerTurn) scheduleComputer();
  retry();
})();
