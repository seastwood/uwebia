window.VideoLibraryModal = (function () {
    let selectedAssets = new Map();
    let currentFolderId = null;
    let currentSectionId = null;
    let currentMode = 'multiple';
    let onConfirmCallback = null;

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

        const modal = qs('videoLibraryModal');
        const subtitle = qs('videoLibraryModalSubtitle');

        if (subtitle) {
            subtitle.textContent = options.subtitle || 'Choose video files from your Asset Library.';
        }

        if (modal) {
            modal.style.display = 'block';
        }

        loadRoot();
        updateSelectionCount();
    }

    function close() {
        const modal = qs('videoLibraryModal');
        if (modal) modal.style.display = 'none';

        selectedAssets.clear();
        currentFolderId = null;
        currentSectionId = null;
        onConfirmCallback = null;
        pauseModalVideos();
        updateSelectionCount();
    }

    function pauseModalVideos() {
        document.querySelectorAll('#videoLibraryModal video').forEach(video => {
            video.pause();
        });
    }

    async function loadRoot() {
        currentFolderId = null;

        const response = await fetch('/admin/assets/root?type=video');
        const data = await response.json();

        renderFolders(data.folders || []);
        renderAssets(data.assets || []);

        const folderName = qs('videoModalCurrentFolderName');
        if (folderName) folderName.textContent = 'Root Videos';
    }

    async function loadFolder(folderId, folderName = 'Folder') {
        currentFolderId = folderId;

        const response = await fetch(`/admin/assets/folder/${folderId}?type=video`);
        const data = await response.json();

        renderAssets(data.assets || []);

        const folderNameEl = qs('videoModalCurrentFolderName');
        if (folderNameEl) folderNameEl.textContent = folderName;
    }

    function renderFolders(folders) {
        const grid = qs('videoModalFolderGrid');
        if (!grid) return;

        grid.innerHTML = '';

        const root = document.createElement('div');
        root.className = 'folder-item active-folder';
        root.innerHTML = `
            <i class="fas fa-home fa-3x"></i>
            <p>Main Videos</p>
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
        const grid = qs('videoModalVideoGrid');
        if (!grid) return;

        grid.innerHTML = '';

        if (!assets.length) {
            grid.innerHTML = `
                <div class="video-modal-empty">
                    No video files here yet.
                </div>
            `;
            return;
        }

        assets.forEach(asset => {
            const selected = selectedAssets.has(Number(asset.id));

            const card = document.createElement('div');
            card.className = `video-modal-card ${selected ? 'selected' : ''}`;
            card.dataset.assetId = asset.id;

            card.innerHTML = `
                <button type="button" class="video-select-toggle" title="Select video">
                    <i class="fas ${selected ? 'fa-check-circle' : 'fa-circle'}"></i>
                </button>

<button type="button"
        class="video-modal-preview-button"
        data-video-url="${escapeHtml(asset.url)}"
        data-video-mime="${escapeHtml(asset.mime_type || 'video/mp4')}"
        data-video-title="${escapeHtml(asset.original_filename || 'Video Preview')}">

    <canvas class="video-modal-thumb-canvas" aria-hidden="true"></canvas>

    <div class="video-modal-thumb-fallback">
        <span class="video-modal-play-icon" aria-hidden="true"></span>
        <span>Preview Video</span>
    </div>
</button>

                <div class="video-modal-info">
                    <div class="video-modal-title" title="${escapeHtml(asset.original_filename)}">
                        ${escapeHtml(asset.original_filename)}
                    </div>
                    <div class="video-modal-subtitle">
                        ${(asset.extension || '').toUpperCase()} · ${escapeHtml(asset.file_size_label || '')}
                    </div>
                </div>
            `;

            card.querySelector('.video-select-toggle').addEventListener('click', function (event) {
                event.preventDefault();
                event.stopPropagation();
                toggleAsset(asset);
            });

            card.addEventListener('click', function (event) {
                if (event.target.closest('video')) return;
                toggleAsset(asset);
            });

            const previewButton = card.querySelector('.video-modal-preview-button');

            if (previewButton) {
                previewButton.addEventListener('click', function (event) {
                    event.preventDefault();
                    event.stopPropagation();

                    openPreview(
                        asset.url,
                        asset.mime_type || 'video/mp4',
                        asset.original_filename || 'Video Preview'
                    );
                });
            }

            grid.appendChild(card);
        });
        generateVideoModalThumbnails();
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
        document.querySelectorAll('#videoModalVideoGrid .video-modal-card').forEach(card => {
            const id = Number(card.dataset.assetId);
            const selected = selectedAssets.has(id);

            card.classList.toggle('selected', selected);

            const icon = card.querySelector('.video-select-toggle i');
            if (icon) {
                icon.className = `fas ${selected ? 'fa-check-circle' : 'fa-circle'}`;
            }
        });
    }

    function updateSelectionCount() {
        const count = selectedAssets.size;
        const label = qs('videoSelectionCount');

        if (label) {
            label.textContent = `${count} ${count === 1 ? 'video' : 'videos'} selected`;
        }
    }

    async function confirmSelection() {
        const selected = Array.from(selectedAssets.values());

        if (!selected.length) {
            alert('Please select at least one video file.');
            return;
        }

        const sectionIdToUpdate = currentSectionId;
        const assetIds = selected.map(asset => asset.id);

        if (onConfirmCallback) {
            onConfirmCallback({
                mode: currentMode,
                assetIds,
                videoIds: assetIds,
                assets: selected,
                sectionId: sectionIdToUpdate
            });
            close();
            return;
        }

        if (!sectionIdToUpdate) {
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
                section_id: sectionIdToUpdate,
                asset_ids: assetIds,
                usage_type: 'section-video'
            })
        });

        const data = await response.json();

        if (data.success || data.status === 'success') {
            close();

            if (typeof loadSectionVideos === 'function') {
                requestAnimationFrame(() => {
                    loadSectionVideos(sectionIdToUpdate);

                    setTimeout(() => {
                        const sectionContent = document.getElementById(`section-content-${sectionIdToUpdate}`);

                        if (
                            sectionContent &&
                            sectionContent.classList.contains('open') &&
                            typeof updateOpenSectionLayout === 'function'
                        ) {
                            updateOpenSectionLayout(sectionContent);
                        }
                    }, 120);
                });
            }

            if (typeof reloadIframe === 'function') {
                reloadIframe();
            }
        } else {
            alert(data.error || data.message || 'Failed to add video.');
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

        const progressWrapper = qs('videoModalUploadProgressWrapper');
        const progressFill = qs('videoModalUploadProgressFill');
        const progressText = qs('videoModalUploadProgressText');

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
                    loadFolder(currentFolderId, qs('videoModalCurrentFolderName')?.textContent || 'Folder');
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
            } catch (_) { }

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
                asset_type: 'video'
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
        loadFolder,
        openPreview,
        closePreview,
        generateVideoModalThumbnails
    };


function openPreview(videoUrl, mimeType, title) {
    const modal = qs('videoLibraryPreviewModal');
    const player = qs('videoLibraryPreviewPlayer');
    const titleEl = qs('videoLibraryPreviewTitle');

    if (!modal || !player) return;

    player.pause();
    player.removeAttribute('src');
    player.innerHTML = '';

    player.src = videoUrl;
    player.type = mimeType || 'video/mp4';
    player.load();

    player.onloadedmetadata = function () {
        console.log('Video library preview loaded:', {
            duration: player.duration,
            width: player.videoWidth,
            height: player.videoHeight
        });
    };

    player.onerror = function () {
        console.error('Video library preview failed:', player.error, videoUrl);
    };

    if (titleEl) {
        titleEl.textContent = title || 'Video Preview';
    }

    modal.classList.add('is-open');
}

function closePreview() {
    const modal = qs('videoLibraryPreviewModal');
    const player = qs('videoLibraryPreviewPlayer');

    if (player) {
        player.pause();
        player.removeAttribute('src');
        player.innerHTML = '';
        player.load();
    }

    if (modal) {
        modal.classList.remove('is-open');
    }
}

function generateVideoModalThumbnails() {
    document.querySelectorAll('#videoLibraryModal .video-modal-preview-button[data-video-url]').forEach(button => {
        if (button.dataset.thumbnailGenerated === 'true') return;

        const videoUrl = button.dataset.videoUrl;
        const canvas = button.querySelector('.video-modal-thumb-canvas');

        if (!videoUrl || !canvas) return;

        button.dataset.thumbnailGenerated = 'true';

        const video = document.createElement('video');

        video.src = videoUrl;
        video.muted = true;
        video.preload = 'metadata';
        video.playsInline = true;

        video.addEventListener('loadedmetadata', function () {
            const targetTime = Math.min(1, Math.max(0, (video.duration || 1) * 0.1));

            try {
                video.currentTime = targetTime;
            } catch (error) {
                console.warn('Could not seek video modal thumbnail:', error);
            }
        });

        video.addEventListener('seeked', function () {
            try {
                const width = video.videoWidth || 320;
                const height = video.videoHeight || 180;

                canvas.width = width;
                canvas.height = height;

                const ctx = canvas.getContext('2d');
                ctx.drawImage(video, 0, 0, width, height);

                button.classList.add('has-thumbnail');

                video.removeAttribute('src');
                video.load();
            } catch (error) {
                console.warn('Could not draw video modal thumbnail:', error);
            }
        });

        video.addEventListener('error', function () {
            console.warn('Could not load video modal thumbnail:', videoUrl, video.error);
        });
    });
}
})();
