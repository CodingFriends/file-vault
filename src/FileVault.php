<?php

namespace CodingFriends\FileVault;

use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use League\Flysystem\AwsS3V3\AwsS3V3Adapter;
use League\Flysystem\FilesystemAdapter;

class FileVault
{
    /**
     * The storage disk.
     *
     * @var string
     */
    protected string $disk = 'local';

    /**
     * The encryption key.
     *
     * @var string
     */
    protected string $key = '';

    /**
     * The algorithm used for encryption.
     *
     * @var string
     */
    protected string $cipher = 'AES-128-CBC';

    /**
     * The storage filesystem adapter.
     *
     * @var FilesystemAdapter
     */
    protected FilesystemAdapter $adapter;

    public function __construct()
    {
        $this->disk = config('file-vault.disk') ?? 'local';
        $this->key = config('file-vault.key') ?? '';
        $this->cipher = config('file-vault.cipher') ?? 'AES-128-CBC';
    }

    /**
     * Set the disk where the files are located.
     *
     * @param string $disk
     * @return $this
     */
    public function disk(string $disk): static
    {
        $this->disk = $disk;

        return $this;
    }

    /**
     * Set the encryption key.
     *
     * @param string $key
     * @return $this
     */
    public function key(string $key): static
    {
        $this->key = $key;

        return $this;
    }

    /**
     * Create a new encryption key for the given cipher.
     *
     * @return string A random key in the appropriate length for the cipher
     * @throws \Exception If not enough randomness can be found
     */
    public static function generateKey(): string
    {
        return random_bytes(config('file-vault.cipher') === 'AES-128-CBC' ? 16 : 32);
    }

    /**
     * Encrypt the passed file and saves the result in a new file with ".enc" as suffix.
     *
     * @param string $sourceFile Path to file that should be encrypted, relative to the storage disk specified
     * @param string|null $destFile File name where the encryped file should be written to, relative to the storage disk specified
     * @return $this
     * @throws \Exception
     */
    public function encrypt(string $sourceFile, string $destFile = null, $deleteSource = true): static
    {
        $this->registerServices();

        if (is_null($destFile)) {
            $destFile = "{$sourceFile}.enc";
        }

        $sourcePath = $this->getFilePath($sourceFile);
        $destPath = $this->getFilePath($destFile);

        // Create a new encrypter instance
        $encrypter = new FileEncrypter($this->key, $this->cipher);

        // If encryption is successful, delete the source file
        if ($encrypter->encrypt($sourcePath, $destPath) && $deleteSource) {
            Storage::disk($this->disk)->delete($sourceFile);
        }

        return $this;
    }

    /**
     * Creates an encrypted copy of the given source file.
     *
     * @throws \Exception
     */
    public function encryptCopy($sourceFile, $destFile = null): static
    {
        return self::encrypt($sourceFile, $destFile, false);
    }

    /**
     * Dencrypt the passed file and saves the result in a new file, removing the
     * last 4 characters from file name.
     *
     * @param string $sourceFile Path to file that should be decrypted
     * @param string|null $destFile   File name where the decryped file should be written to.
     * @return $this
     */
    public function decrypt(string $sourceFile, string $destFile = null, $deleteSource = true)
    {
        $this->registerServices();

        if (is_null($destFile)) {
            $destFile = Str::endsWith($sourceFile, '.enc')
                        ? Str::replaceLast('.enc', '', $sourceFile)
                        : $sourceFile.'.dec';
        }

        $sourcePath = $this->getFilePath($sourceFile);
        $destPath = $this->getFilePath($destFile);

        // Create a new encrypter instance
        $encrypter = new FileEncrypter($this->key, $this->cipher);

        // If decryption is successful, delete the source file
        if ($encrypter->decrypt($sourcePath, $destPath) && $deleteSource) {
            Storage::disk($this->disk)->delete($sourceFile);
        }

        return $this;
    }

    public function decryptCopy($sourceFile, $destFile = null)
    {
        return self::decrypt($sourceFile, $destFile, false);
    }

    public function streamDecrypt($sourceFile): bool
    {
        $this->registerServices();

        $sourcePath = $this->getFilePath($sourceFile);

        // Create a new encrypter instance
        $encrypter = new FileEncrypter($this->key, $this->cipher);

        return $encrypter->decrypt($sourcePath, 'php://output');
    }

    protected function getFilePath($file): string
    {
        if ($this->isS3File()) {
            return "s3://{$this->adapter->getBucket()}/{$file}";
        }

        return Storage::disk($this->disk)->path($file);
    }

    /**
     * Indicates if the storage adapter is an S3 adapter.
     *
     * @return bool `true` if S3
     */
    protected function isS3File(): bool
    {
        return $this->adapter instanceof AwsS3V3Adapter;
    }

    /**
     * Sets the adapter to the current disk's adapter.
     *
     * @return void
     */
    protected function setAdapter()
    {
        $this->adapter = Storage::disk($this->disk)->getAdapter();
    }

    /**
     * Updates the adapter and sets the stream client if necessary.
     *
     * @return void
     */
    protected function registerServices()
    {
        $this->setAdapter();

        if ($this->isS3File()) {
            $client = $this->adapter->getClient();
            $client->registerStreamWrapper();
        }
    }
}
