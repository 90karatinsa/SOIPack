export class DeleteObjectsCommand {
  constructor(public readonly input?: unknown) {}
}

export class GetObjectCommand {
  constructor(public readonly input?: unknown) {}
}

export class ListObjectsV2Command {
  constructor(public readonly input?: unknown) {}
}

export class PutObjectCommand {
  constructor(public readonly input?: unknown) {}
}

export class S3Client {
  constructor(public readonly config?: unknown) {}

  // eslint-disable-next-line @typescript-eslint/class-methods-use-this
  async send(): Promise<unknown> {
    return {};
  }
}
