window.MusicLibraryModal = (function () {
    let selectedAssets = new Map();
    let currentFolderId = null;
    let currentSectionId = null;
    let currentMode = 'multiple';
    let onConfirmCallback = null;

    const allowedType = 'audio';

    function qs(id) {
        return document.getElementById(id);
    }

    function escapeHtml(value) {
        return String(value ?? '')
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#039;');
    }

    function open(options = {}) {
        currentSectionId = options.sectionId || null;
        currentMode = options.mode || 'multiple';
        onConfirmCallback = options.onConfirm || null;
        selectedAssets.clear();
        currentFolderId = null;

        const modal = qs('musicLibraryModal');
        const subtitle = qs('musicLibraryModalSubtitle');

        if (subtitle) {
            subtitle.textContent = options.subtitle || 'Choose audio files from your Asset Library.';
        }

        if (modal) {
            modal.style.display = 'block';
        }

        loadRoot();
        updateSelectionCount();
    }

    function close() {
        const modal = qs('musicLibraryModal');
        if (modal) modal.style.display = 'none';

        selectedAssets.clear();
        currentFolderId = null;
        currentSectionId = null;
        onConfirmCallback = null;
        pauseModalAudio();
        updateSelectionCount();
    }

    function pauseModalAudio() {
        document.querySelectorAll('#musicLibraryModal audio').forEach(audio => {
            audio.pause();
        });
    }

    async function loadRoot() {
        currentFolderId = null;

        const response = await fetch('/admin/assets/root?type=audio');
        const data = await response.json();

        renderFolders(data.folders || []);
        renderAssets(data.assets || []);

        const folderName = qs('musicModalCurrentFolderName');
        if (folderName) folderName.textContent = 'Root Audio';
    }

    async function loadFolder(folderId, folderName = 'Folder') {
        currentFolderId = folderId;

        const response = await fetch(`/admin/assets/folder/${folderId}?type=audio`);
        const data = await response.json();

        renderAssets(data.assets || []);

        const folderNameEl = qs('musicModalCurrentFolderName');
        if (folderNameEl) folderNameEl.textContent = folderName;
    }

    function renderFolders(folders) {
        const grid = qs('musicModalFolderGrid');
        if (!grid) return;

        grid.innerHTML = '';

        const root = document.createElement('div');
        root.className = 'folder-item active-folder';
        root.innerHTML = `
            <i class="fas fa-home fa-3x"></i>
            <p>Main Audio</p>
        `;
        root.addEventListener('click', loadRoot);
        grid.appendChild(root);

        folders.forEach(folder => {
            const item = document.createElement('div');
            item.className = 'folder-item';
            item.innerHTML = `
                <i class="fas fa-folder fa-3x"></i>
                <p>${escapeHtml(folder.name)}</p>
            `;
            item.addEventListener('click', () => loadFolder(folder.id, folder.name));
            grid.appendChild(item);
        });
    }

    function renderAssets(assets) {
        const grid = qs('musicModalAudioGrid');
        if (!grid) return;

        grid.innerHTML = '';

        if (!assets.length) {
            grid.innerHTML = `
                <div class="music-modal-empty">
                    No audio files here yet.
                </div>
            `;
            return;
        }

        assets.forEach(asset => {
            const selected = selectedAssets.has(Number(asset.id));

            const row = document.createElement('div');
            row.className = `music-modal-track ${selected ? 'selected' : ''}`;
            row.dataset.assetId = asset.id;

            row.innerHTML = `
                <button type="button" class="music-select-toggle" title="Select track">
                    <i class="fas ${selected ? 'fa-check-circle' : 'fa-circle'}"></i>
                </button>

                <div class="music-modal-track-icon">
                    <i class="fas fa-music"></i>
                </div>

                <div class="music-modal-track-info">
                    <div class="music-modal-track-title" title="${escapeHtml(asset.original_filename)}">
                        ${escapeHtml(asset.original_filename)}
                    </div>
                    <div class="music-modal-track-subtitle">
                        ${(asset.extension || '').toUpperCase()} · ${escapeHtml(asset.file_size_label || '')}
                    </div>
                </div>

                <audio controls preload="metadata"
       onclick="event.stopPropagation();"
       onmousedown="event.stopPropagation();"
       draggable="false"
       ondragstart="event.preventDefault();">
                    <source src="${escapeHtml(asset.url)}" type="${escapeHtml(asset.mime_type || 'audio/mpeg')}">
                    Your browser does not support the audio element.
                </audio>
            `;

            row.querySelector('.music-select-toggle').addEventListener('click', function (event) {
                event.preventDefault();
                event.stopPropagation();
                toggleAsset(asset);
            });

            row.addEventListener('click', function (event) {
                if (event.target.closest('audio')) return;
                toggleAsset(asset);
            });

            grid.appendChild(row);
        });
    }

    function toggleAsset(asset) {
        const id = Number(asset.id);

        if (currentMode === 'single') {
            selectedAssets.clear();
            selectedAssets.set(id, asset);
        } else if (selectedAssets.has(id)) {
            selectedAssets.delete(id);
        } else {
            selectedAssets.set(id, asset);
        }

        updateVisibleSelections();
        updateSelectionCount();
    }

    function updateVisibleSelections() {
        document.querySelectorAll('#musicModalAudioGrid .music-modal-track').forEach(row => {
            const id = Number(row.dataset.assetId);
            const selected = selectedAssets.has(id);

            row.classList.toggle('selected', selected);

            const icon = row.querySelector('.music-select-toggle i');
            if (icon) {
                icon.className = `fas ${selected ? 'fa-check-circle' : 'fa-circle'}`;
            }
        });
    }

    function updateSelectionCount() {
        const count = selectedAssets.size;
        const label = qs('musicSelectionCount');

        if (label) {
            label.textContent = `${count} ${count === 1 ? 'track' : 'tracks'} selected`;
        }
    }

    async function confirmSelection() {
        const selected = Array.from(selectedAssets.values());

        if (!selected.length) {
            alert('Please select at least one audio file.');
            return;
        }

        const assetIds = selected.map(asset => asset.id);
        const assetUrls = selected.map(asset => asset.url);

        const payload = {
            mode: currentMode,
            assetIds,
            audioIds: assetIds,
            assetUrls,
            audioUrls: assetUrls,
            assets: selected,
            sectionId: currentSectionId
        };

        if (onConfirmCallback) {
            onConfirmCallback(payload);
            close();
            return;
        }

        if (!currentSectionId) {
            close();
            return;
        }

        const response = await fetch('/add_assets_to_section', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': typeof csrfToken !== 'undefined' ? csrfToken : ''
            },
            body: JSON.stringify({
                section_id: currentSectionId,
                asset_ids: assetIds,
                usage_type: 'section-music'
            })
        });

        const data = await response.json();

        if (data.success || data.status === 'success') {
    const sectionIdToUpdate = currentSectionId;

    close();

    if (typeof loadSectionMusic === 'function') {
        requestAnimationFrame(() => {
            loadSectionMusic(sectionIdToUpdate);

            setTimeout(() => {
                const sectionContent = document.getElementById(`section-content-${sectionIdToUpdate}`);

                if (sectionContent && sectionContent.classList.contains('open')) {
                    updateOpenSectionLayout(sectionContent);
                }
            }, 120);
        });
    }

    if (typeof reloadIframe === 'function') {
        reloadIframe();
    }
} else {
    alert(data.error || data.message || 'Failed to add music.');
}
    }

    async function handleUpload(event) {
        const files = event.target.files;
        if (!files || !files.length) return;

        const formData = new FormData();

        Array.from(files).forEach(file => {
            formData.append('asset', file);
        });

        if (currentFolderId) {
            formData.append('folder_id', currentFolderId);
        }

        const progressWrapper = qs('musicModalUploadProgressWrapper');
        const progressFill = qs('musicModalUploadProgressFill');
        const progressText = qs('musicModalUploadProgressText');

        if (progressWrapper) progressWrapper.style.display = 'block';
        if (progressFill) progressFill.style.width = '0%';
        if (progressText) progressText.textContent = '0%';

        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/admin/assets/upload', true);

        xhr.upload.addEventListener('progress', function (e) {
            if (!e.lengthComputable) return;

            const percent = Math.round((e.loaded / e.total) * 100);

            if (progressFill) progressFill.style.width = `${percent}%`;
            if (progressText) progressText.textContent = `${percent}%`;
        });

        xhr.onload = function () {
            event.target.value = '';

            if (xhr.status >= 200 && xhr.status < 300) {
                if (progressFill) progressFill.style.width = '100%';
                if (progressText) progressText.textContent = 'Upload complete';

                if (currentFolderId) {
                    loadFolder(currentFolderId, qs('musicModalCurrentFolderName')?.textContent || 'Folder');
                } else {
                    loadRoot();
                }

                setTimeout(() => {
                    if (progressWrapper) progressWrapper.style.display = 'none';
                }, 600);

                return;
            }

            let message = 'Upload failed.';

            try {
                const data = JSON.parse(xhr.responseText);
                message = data.error || data.message || message;
            } catch (_) {}

            alert(message);

            if (progressWrapper) progressWrapper.style.display = 'none';
        };

        xhr.onerror = function () {
            alert('Upload failed.');
            if (progressWrapper) progressWrapper.style.display = 'none';
        };

        xhr.send(formData);
    }

    async function createFolder() {
        const folderName = prompt('Folder name:');

        if (!folderName) return;

        const response = await fetch('/admin/assets/create_folder', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': typeof csrfToken !== 'undefined' ? csrfToken : ''
            },
            body: JSON.stringify({
                name: folderName,
                asset_type: allowedType
            })
        });

        const data = await response.json();

        if (data.success || data.status === 'success') {
            loadRoot();
        } else {
            alert(data.message || data.error || 'Failed to create folder.');
        }
    }

    return {
        open,
        close,
        confirmSelection,
        handleUpload,
        createFolder,
        loadRoot,
        loadFolder
    };
})();