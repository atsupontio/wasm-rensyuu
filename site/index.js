// import("./node_modules/hello-wasm/hello_wasm.js").then((js) => {
//     import("./node_modules/hello-wasm/hello_wasm_bg.wasm").then((memory) => {

//         const CELL_SIZE = 5; // px
//         const GRID_COLOR = "#CCCCCC";
//         const DEAD_COLOR = "#FFFFFF";
//         const ALIVE_COLOR = "#000000";

//         // const pre = document.getElementById("game-of-life-canvas");
//         const universe = js.Universe.new();
//         console.log('uni', universe.render());
//         const width = universe.width();
//         const height = universe.height();
//         console.log('width: ', width);

//         // Give the canvas room for all of our cells and a 1px border
//         // around each of them.
//         const canvas = document.getElementById("game-of-life-canvas");
//         canvas.height = (CELL_SIZE + 1) * height + 1;
//         canvas.width = (CELL_SIZE + 1) * width + 1;

//         const ctx = canvas.getContext('2d');

//         const drawGrid = () => {
//             ctx.beginPath();
//             ctx.strokeStyle = GRID_COLOR;
        
//             // Vertical lines.
//             for (let i = 0; i <= width; i++) {
//             ctx.moveTo(i * (CELL_SIZE + 1) + 1, 0);
//             ctx.lineTo(i * (CELL_SIZE + 1) + 1, (CELL_SIZE + 1) * height + 1);
//             }
        
//             // Horizontal lines.
//             for (let j = 0; j <= height; j++) {
//             ctx.moveTo(0,                           j * (CELL_SIZE + 1) + 1);
//             ctx.lineTo((CELL_SIZE + 1) * width + 1, j * (CELL_SIZE + 1) + 1);
//             }
        
//             ctx.stroke();
//         };
        
//         const getIndex = (row, column) => {
//             return row * width + column;
//         };
          
//         const drawCells = () => {
//             const cellsPtr = universe.cells();
//             const cells = new Uint8Array(memory.memory.buffer, cellsPtr, width * height);
          
//             ctx.beginPath();
          
//             for (let row = 0; row < height; row++) {
//               for (let col = 0; col < width; col++) {
//                 const idx = getIndex(row, col);
          
//                 ctx.fillStyle = cells[idx] === js.Cell.Dead
//                   ? DEAD_COLOR
//                   : ALIVE_COLOR;
//                   // console.log('a: ', ctx.fillStyle);
          
//                 ctx.fillRect(
//                   col * (CELL_SIZE + 1) + 1,
//                   row * (CELL_SIZE + 1) + 1,
//                   CELL_SIZE,
//                   CELL_SIZE
//                 );
//               }
//             }
          
//             ctx.stroke();
//         };

//         let animationId = null;

//         const isPaused = () => {
//             return animationId === null;
//         };
        
//         const playPauseButton = document.getElementById("play-pause");

//         const play = () => {
//         playPauseButton.textContent = "⏸";
//         renderLoop();
//         };

//         const pause = () => {
//         playPauseButton.textContent = "▶";
//         cancelAnimationFrame(animationId);
//         animationId = null;
//         };

//         playPauseButton.addEventListener("click", event => {
//         if (isPaused()) {
//             play();
//         } else {
//             pause();
//         }
//         });


//         const renderLoop = () => {
//             universe.tick();

//             drawGrid();
//             drawCells();
        
//             animationId = requestAnimationFrame(renderLoop);
//         }; 
        
//         drawGrid();
//         drawCells();
//         play();

//     })
// }).catch(console.error);

import("./node_modules/hello-wasm/hello_wasm.js").then((js) => {

    const CreateProofButton = document.getElementById("create-proof-button");
    const ShowVkeyButton = document.getElementById("show-vkey-button");
    const CopySetupButton = document.getElementById("copy-vkey-button");
    const CopyProofButton = document.getElementById("copy-proof-button");
    const CopyCIDButton = document.getElementById("copy-CID-button");
    const CopyNameBirthHashButton = document.getElementById("copy-name-birth-hash-button");

        const createProof = () => {
            var name = document.getElementById("name").value;
            var birth = document.getElementById("birthday").value;
            var secret = document.getElementById("secret").value;
            var nonce = document.getElementById("nonce").value;
            var id = document.getElementById("id").value;

            var result = js.create_proof(id, secret, nonce, name, birth);
            var CID = js.get_CID(id, secret, nonce, name, birth);
            var name_birth_hash = js.get_hash_name_birth(name, birth);
            document.getElementById("proof").innerHTML = "0x" + result;
            document.getElementById("CID").innerHTML = "0x" + CID;
            document.getElementById("name-birth-hash").innerHTML = "0x" + name_birth_hash;
        }


        const showVkey = () => {
            var res = js.get_vkey();
            res = "0x" + res; 
            document.getElementById("vkey").innerHTML = res;
            console.log("show vkey: ", res,);
        }
        ShowVkeyButton.addEventListener("click", event => {
            showVkey();
            console.log("clicked vkey");
        });

        CreateProofButton.addEventListener("click", event => {
            createProof();
            console.log("clicked proof");
        });

        
        const copyToClipboard = (result) => {
            var copyText = document.getElementById(result);
            navigator.clipboard.writeText(copyText.innerText).then(function() {
              alert("コピーしました: " + copyText.innerText);
            }, function(err) {
              console.error("コピーに失敗しました: ", err);
            });
        }
        CopySetupButton.addEventListener("click", event => {
            copyToClipboard("vkey")
        });

        CopyProofButton.addEventListener("click", event => {
            copyToClipboard("proof")
        });

        CopyCIDButton.addEventListener("click", event => {
            copyToClipboard("CID")
        });

        CopyNameBirthHashButton.addEventListener("click", event => {
            copyToClipboard("name-birth-hash")
        });

}).catch(console.error);

